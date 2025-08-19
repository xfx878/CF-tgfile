// The limitation of tg means that although files over 20M can be uploaded, a direct link address cannot be returned.
// Therefore, the code is modified to directly prevent uploading when the file is larger than 20MB.

// Database initialization function
async function initDatabase(config) {
  await config.database.prepare(`
    CREATE TABLE IF NOT EXISTS files (
      url TEXT PRIMARY KEY,
      fileId TEXT NOT NULL,
      message_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      file_name TEXT,
      file_size INTEGER,
      mime_type TEXT,
      password TEXT
    )
  `).run();
}

// Exported functions
export default {
  async fetch(request, env) {
    // Environment variable configuration
    const config = {
      domain: env.DOMAIN,
      database: env.DATABASE,
      username: env.USERNAME,
      password: env.PASSWORD,
      enableAuth: env.ENABLE_AUTH === 'true',
      tgBotToken: env.TG_BOT_TOKEN,
      tgChatId: env.TG_CHAT_ID,
      cookie: Number(env.COOKIE) || 7, // cookie expiration defaults to 7 days
      maxSizeMB: Number(env.MAX_SIZE_MB) || 20 // Single file upload size defaults to 20M
    };

    // Initialize database
    await initDatabase(config);
    // Route handling
    const { pathname } = new URL(request.url);

    if (pathname === '/config') {
      const safeConfig = { maxSizeMB: config.maxSizeMB };
      return new Response(JSON.stringify(safeConfig), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const routes = {
      '/': () => handleAuthRequest(request, config),
      '/login': () => handleLoginRequest(request, config),
      '/upload': () => handleUploadRequest(request, config),
      '/admin': () => handleAdminRequest(request, config),
      '/delete': () => handleDeleteRequest(request, config),
      '/update': () => handleUpdateRequest(request, config), // New route for editing file info
      '/search': () => handleSearchRequest(request, config),
      '/bing': () => handleBingImagesRequest(request)
    };
    const handler = routes[pathname];
    if (handler) {
      return await handler();
    }
    // Handle file access requests
    return await handleFileRequest(request, config);
  }
};

// Handle authentication
function authenticate(request, config) {
  const cookies = request.headers.get("Cookie") || "";
  const authToken = cookies.match(/auth_token=([^;]+)/); // Get auth_token from cookie
  if (authToken) {
    try {
      // Decode token, verify expiration
      const tokenData = JSON.parse(atob(authToken[1]));
      const now = Date.now();           
      // Check if token has expired
      if (now > tokenData.expiration) {
        console.log("Token has expired");
        return false;
      }          
      // If token is valid, return whether username matches
      return tokenData.username === config.username;
    } catch (error) {
      console.error("Token username does not match", error);
      return false;
    }
  }
  return false;
}

// Handle routing
async function handleAuthRequest(request, config) {
  if (config.enableAuth) {
    // Use authenticate function to check if user is authenticated
    const isAuthenticated = authenticate(request, config);
    if (!isAuthenticated) {
      return handleLoginRequest(request, config);  // Authentication failed, redirect to login page
    }
    return handleUploadRequest(request, config);  // Authentication successful, redirect to upload page
  }
  // If authentication is not enabled, go directly to the upload page
  return handleUploadRequest(request, config);
}

// Handle login
async function handleLoginRequest(request, config) {
  if (request.method === 'POST') {
    const { username, password } = await request.json();
    
    if (username === config.username && password === config.password) {
      // Login successful, set a cookie valid for 7 days
      const expirationDate = new Date();
      expirationDate.setDate(expirationDate.getDate() + config.cookie);
      const expirationTimestamp = expirationDate.getTime();
      // Create token data, including username and expiration time
      const tokenData = JSON.stringify({
        username: config.username,
        expiration: expirationTimestamp
      });

      const token = btoa(tokenData);  // Base64 encode
      const cookie = `auth_token=${token}; Path=/; HttpOnly; Secure; Expires=${expirationDate.toUTCString()}`;
      return new Response("登录成功", {
        status: 200,
        headers: {
          "Set-Cookie": cookie,
          "Content-Type": "text/plain"
        }
      });
    }
    return new Response("认证失败", { status: 401 });
  }
  const html = generateLoginPage();  // If it's a GET request, return the login page
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

// Handle file upload
async function handleUploadRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return Response.redirect(`${new URL(request.url).origin}/`, 302);
  }
  if (request.method === 'GET') {
    const html = generateUploadPage();
    return new Response(html, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' }
    });
  }

  try {
    const formData = await request.formData();
    const file = formData.get('file');
    const password = formData.get('password'); // Get password from form
    if (!file) throw new Error('未找到文件');
    if (file.size > config.maxSizeMB * 1024 * 1024) throw new Error(`文件超过${config.maxSizeMB}MB限制`);
    
    const ext = (file.name.split('.').pop() || '').toLowerCase();  // Get file extension
    const mimeType = getContentType(ext);  // Get file type
    const [mainType] = mimeType.split('/'); // Get main type
    // Define type mapping
    const typeMap = {
      image: { method: 'sendPhoto', field: 'photo' },
      video: { method: 'sendVideo', field: 'video' },
      audio: { method: 'sendAudio', field: 'audio' }
    };
    let { method = 'sendDocument', field = 'document' } = typeMap[mainType] || {};

    if (['application', 'text'].includes(mainType)) {
      method = 'sendDocument';
      field = 'document';
    }

    const tgFormData = new FormData();
      tgFormData.append('chat_id', config.tgChatId);
      tgFormData.append(field, file, file.name);      
    const tgResponse = await fetch(
      `https://api.telegram.org/bot${config.tgBotToken}/${method}`,
      { method: 'POST', body: tgFormData }
    ); 
    if (!tgResponse.ok) throw new Error('Telegram参数配置错误');  

    const tgData = await tgResponse.json();
    const result = tgData.result;
    const messageId = tgData.result?.message_id;
    const fileId = result?.document?.file_id ||
                   result?.video?.file_id ||
                   result?.audio?.file_id ||
                  (result?.photo && result.photo[result.photo.length-1]?.file_id);
    if (!fileId) throw new Error('未获取到文件ID');
    if (!messageId) throw new Error('未获取到tg消息ID');

    const time = Date.now();
    const timestamp = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();
    const url = `https://${config.domain}/${time}.${ext}`;
    
    await config.database.prepare(`
      INSERT INTO files (url, fileId, message_id, created_at, file_name, file_size, mime_type, password) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      url,
      fileId,
      messageId,
      timestamp,
      file.name,
      file.size,
      file.type || getContentType(ext),
      password || null // Store password, or null if not provided
    ).run();

    return new Response(
      JSON.stringify({ status: 1, msg: "✔ 上传成功", url }),
      { headers: { 'Content-Type': 'application/json' }}
    );

  } catch (error) {
    console.error(`[Upload Error] ${error.message}`);
    let statusCode = 500;
    if (error.message.includes(`文件超过${config.maxSizeMB}MB限制`)) {
      statusCode = 400;
    } else if (error.message.includes('Telegram参数配置错误')) {
      statusCode = 502;
    } else if (error.message.includes('未获取到文件ID') || error.message.includes('未获取到tg消息ID')) {
      statusCode = 500;
    } else if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
      statusCode = 504;
    }
    return new Response(
      JSON.stringify({ status: 0, msg: "✘ 上传失败", error: error.message }),
      { status: statusCode, headers: { 'Content-Type': 'application/json' }}
    );
  }
}

// Handle file management and preview
async function handleAdminRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return Response.redirect(`${new URL(request.url).origin}/`, 302);
  }

  const { results } = await config.database.prepare(
    `SELECT url, fileId, message_id, created_at, file_name, file_size, mime_type, password
    FROM files
    ORDER BY created_at DESC`
  ).all();

  const fileList = results || [];
  const totalFiles = fileList.length; // Get total file count

  const fileCards = fileList.map(file => {
    const fileName = file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    return `
      <div class="file-card" data-url="${file.url}">
        <input type="checkbox" class="file-checkbox" value="${file.url}">
        <div class="file-preview">
          ${getPreviewHtml(file.url)}
        </div>
        <div class="file-info">
          <div>${fileName}</div>
          <div>${fileSize}</div>
          <div>${createdAt}</div>
          ${file.password ? `<div class="password-info" onclick="copyPassword('${file.password}', this)">点击复制密码</div>` : ''}
        </div>
        <div class="file-actions">
          <button class="btn btn-copy" onclick="showQRCode('${file.url}')">分享</button>
          <button class="btn btn-edit" onclick="openEditModal('${file.url}', '${file.file_name.replace(/'/g, "\\'")}', '${file.password || ''}')">编辑</button>
          <a class="btn btn-down" href="${file.url}" download="${fileName}">下载</a>
          <button class="btn btn-delete" onclick="deleteSingleFile('${file.url}')">删除</button>
        </div>
      </div>
    `;
  }).join('');

  const qrModal = `
    <div id="qrModal" class="modal">
      <div class="modal-content">
        <h3>分享文件</h3>
        <div id="qrcode"></div>
        <div class="share-link-container">
          <a id="shareLink" href="#" target="_blank"></a>
          <button id="copyLinkBtn" onclick="handleCopyUrl()">复制</button>
        </div>
        <div class="modal-buttons">
          <button onclick="closeModal('qrModal')">关闭</button>
        </div>
      </div>
    </div>
  `;

  const editModal = `
    <div id="editModal" class="modal">
      <div class="modal-content">
        <h3>编辑文件信息</h3>
        <input type="hidden" id="editFileUrl">
        <div class="form-group">
          <label for="editFileName">文件名:</label>
          <input type="text" id="editFileName">
        </div>
        <div class="form-group">
          <label for="editFilePassword">密码 (留空则不设密码):</label>
          <input type="text" id="editFilePassword">
        </div>
        <div class="modal-buttons">
          <button onclick="saveFileChanges()">保存</button>
          <button onclick="closeModal('editModal')">取消</button>
        </div>
      </div>
    </div>
  `;

  const html = generateAdminPage(fileCards, qrModal, editModal, totalFiles);
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

// Handle file info updates
async function handleUpdateRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ error: '未授权' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  try {
    const { url, fileName, password } = await request.json();
    if (!url || !fileName) {
      return new Response(JSON.stringify({ error: '无效的请求' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    await config.database.prepare(
      'UPDATE files SET file_name = ?, password = ? WHERE url = ?'
    ).bind(fileName, password || null, url).run();

    // Clear cache for the updated file
    const cache = caches.default;
    await cache.delete(new Request(url));

    return new Response(JSON.stringify({ success: true, message: '更新成功' }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error(`[Update Error] ${error.message}`);
    return new Response(JSON.stringify({ error: '更新失败' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}


// Handle file search
async function handleSearchRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return Response.redirect(`${new URL(request.url).origin}/`, 302);
  }

  try {
    const { query } = await request.json();
    const searchPattern = `%${query}%`;    
    const files = await config.database.prepare(
      `SELECT url, fileId, message_id, created_at, file_name, file_size, mime_type
       FROM files 
       WHERE file_name LIKE ? ESCAPE '!'
       COLLATE NOCASE
       ORDER BY created_at DESC`
    ).bind(searchPattern).all();

    return new Response(
      JSON.stringify({ files: files.results || [] }),
      { headers: { 'Content-Type': 'application/json' }}
    );

  } catch (error) {
    console.error(`[Search Error] ${error.message}`);
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' }}
    );
  }
}

// Supported file types for preview
function getPreviewHtml(url) {
  const ext = (url.split('.').pop() || '').toLowerCase();
  const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'].includes(ext);
  const isVideo = ['mp4', 'webm'].includes(ext);
  const isAudio = ['mp3', 'wav', 'ogg'].includes(ext);

  if (isImage) {
    return `<img src="${url}" alt="预览" loading="lazy">`;
  } else if (isVideo) {
    return `<video src="${url}" controls></video>`;
  } else if (isAudio) {
    return `<audio src="${url}" controls></audio>`;
  } else {
    return `<div style="font-size: 48px">📄</div>`;
  }
}

// Get file and cache it
async function handleFileRequest(request, config) {
    const url = new URL(request.url);
    const cache = caches.default;
    const cacheKey = new Request(url.origin + url.pathname);

    try {
        const file = await config.database.prepare(
            `SELECT fileId, message_id, file_name, mime_type, password FROM files WHERE url = ?`
        ).bind(url.origin + url.pathname).first();

        if (!file) {
            return new Response('文件不存在', { status: 404, headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
        }

        if (file.password) {
            const passwordCookie = (request.headers.get('Cookie') || '').match(new RegExp(`pw_token_${file.message_id}=([^;]+)`));
            const submittedPassword = passwordCookie ? atob(passwordCookie[1]) : null;

            if (submittedPassword !== file.password) {
                if (request.method === 'POST') {
                    const formData = await request.formData();
                    const inputPassword = formData.get('password');
                    if (inputPassword === file.password) {
                        const expiry = new Date(Date.now() + 3600 * 1000); // 1 hour validity
                        const cookie = `pw_token_${file.message_id}=${btoa(file.password)}; Path=/; Expires=${expiry.toUTCString()}; HttpOnly; Secure`;
                        return new Response(null, { status: 302, headers: { 'Location': url.pathname, 'Set-Cookie': cookie } });
                    } else {
                        return new Response(generatePasswordPage('密码错误，请重试。'), { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
                    }
                }
                return new Response(generatePasswordPage(), { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
            }
        }

        const cachedResponse = await cache.match(cacheKey);
        if (cachedResponse) {
            return cachedResponse;
        }

        const tgResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/getFile?file_id=${file.fileId}`);
        if (!tgResponse.ok) throw new Error('Failed to get file info from Telegram');

        const tgData = await tgResponse.json();
        const filePath = tgData.result?.file_path;
        if (!filePath) throw new Error('Invalid file_path from Telegram');

        const fileUrl = `https://api.telegram.org/file/bot${config.tgBotToken}/${filePath}`;
        const fileResponse = await fetch(fileUrl);
        if (!fileResponse.ok) throw new Error('Failed to download file from Telegram');

        const contentType = file.mime_type || getContentType(url.pathname.split('.').pop().toLowerCase());
        const response = new Response(fileResponse.body, {
            headers: {
                'Content-Type': contentType,
                'Cache-Control': 'public, max-age=31536000',
                'X-Content-Type-Options': 'nosniff',
                'Access-Control-Allow-Origin': '*',
                'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(file.file_name || '')}`
            }
        });

        await cache.put(cacheKey, response.clone());
        return response;

    } catch (error) {
        console.error(`[File Request Error] ${error.message} for ${url}`);
        return new Response('服务器内部错误', { status: 500, headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
    }
}


// Handle file deletion
async function handleDeleteRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ error: '未授权' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  try {
    const { urls } = await request.json();
    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return new Response(JSON.stringify({ error: '无效的URL列表' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    const placeholders = urls.map(() => '?').join(',');
    const files = await config.database.prepare(
      `SELECT url, message_id FROM files WHERE url IN (${placeholders})`
    ).bind(...urls).all();

    if (!files.results || files.results.length === 0) {
      return new Response(JSON.stringify({ error: '未找到文件' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
    }

    const deletePromises = files.results.map(file =>
      fetch(`https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`)
        .catch(err => console.error(`Failed to delete TG message ${file.message_id}:`, err))
    );
    await Promise.all(deletePromises);

    await config.database.prepare(`DELETE FROM files WHERE url IN (${placeholders})`).bind(...urls).run();

    const cache = caches.default;
    for (const url of urls) {
      await cache.delete(new Request(url));
    }

    return new Response(JSON.stringify({ success: true, message: '选中的文件已删除' }), { headers: { 'Content-Type': 'application/json' } });

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}

// Supported upload file types
function getContentType(ext) {
  const types = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/x-icon',
    mp4: 'video/mp4', webm: 'video/webm',
    mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg',
    pdf: 'application/pdf', txt: 'text/plain', md: 'text/markdown',
    zip: 'application/zip', rar: 'application/x-rar-compressed',
    json: 'application/json', xml: 'application/xml',
    js: 'application/javascript', css: 'text/css', html: 'text/html',
    // Add more types as needed
  };
  return types[ext] || 'application/octet-stream'; // Default for unknown types
}

async function handleBingImagesRequest(request) {
  const cache = caches.default;
  const cacheKey = new Request('https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=5', request);
  
  const cachedResponse = await cache.match(cacheKey);
  if (cachedResponse) {
    return cachedResponse;
  }
  
  try {
    const res = await fetch(cacheKey);
    if (!res.ok) {
      throw new Error(`Bing API request failed with status: ${res.status}`);
    }
    
    const bingData = await res.json();
    const images = bingData.images.map(image => ({ url: `https://cn.bing.com${image.url}` }));
    const returnData = { status: true, message: "操作成功", data: images };
    
    const response = new Response(JSON.stringify(returnData), { 
      status: 200, 
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=21600', // Cache for 6 hours
        'Access-Control-Allow-Origin': '*' 
      }
    });
    
    await cache.put(cacheKey, response.clone());
    return response;
  } catch (error) {
    console.error('Error during Bing API request:', error);
    return new Response('请求 Bing API 失败', { status: 500 });
  }
}

// File size calculation function
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${units[i]}`;
}

// Password entry page generation function
function generatePasswordPage(error = '') {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <title>请输入密码</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta charset="UTF-8">
    <style>
      body { display: flex; justify-content: center; align-items: center; height: 100vh; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f0f2f5; margin: 0; }
      .container { background: white; padding: 30px 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; width: 90%; max-width: 350px; }
      h3 { margin-top: 0; }
      input[type="password"] { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
      button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
      button:hover { background: #0056b3; }
      .error { color: #dc3545; margin-bottom: 10px; font-size: 14px; }
    </style>
  </head>
  <body>
    <div class="container">
      <form method="POST">
        <h3>此文件受密码保护</h3>
        <p>请输入密码访问</p>
        ${error ? `<div class="error">${error}</div>` : ''}
        <input type="password" name="password" required autofocus>
        <button type="submit">提交</button>
      </form>
    </div>
  </body>
  </html>`;
}


// Login page generation function /login
function generateLoginPage() {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <link rel="shortcut icon" href="https://pan.811520.xyz/2025-02/1739241502-tgfile-favicon.ico" type="image/x-icon">
  <meta name="description" content="Telegram文件存储与分享平台">
  <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录</title>
    <style>
      body {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        background-size: cover;
        background-position: center;
        font-family: Arial, sans-serif;
        transition: background-image 1s ease-in-out;
      }
      .login-container {
        background: rgba(255, 255, 255, 0.8);
        backdrop-filter: blur(5px);
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        width: 100%;
        max-width: 400px;
      }
      .form-group { margin-bottom: 1rem; }
      input {
        width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px;
        font-size: 1rem; box-sizing: border-box; background: rgba(255, 255, 255, 0.7); color: #333;
      }
      button {
        width: 100%; padding: 0.75rem; background: #007bff; color: white; border: none;
        border-radius: 4px; font-size: 1rem; cursor: pointer; margin-bottom: 10px;
      }
      button:hover { background: #0056b3; }
      .error { color: #dc3545; margin-top: 1rem; display: none; }
    </style>
  </head>
  <body>
    <div class="login-container">
      <h2 style="text-align: center; margin-bottom: 2rem;">登录</h2>
      <form id="loginForm">
        <div class="form-group"><input type="text" id="username" placeholder="用户名" required></div>
        <div class="form-group"><input type="password" id="password" placeholder="密码" required></div>
        <button type="submit">登录</button>
        <div id="error" class="error">用户名或密码错误</div>
      </form>
    </div>
    <script>
      async function setBingBackground() {
        try {
          const response = await fetch('/bing');
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) { console.error('获取背景图失败:', error); }
      }
      setBingBackground(); 
      setInterval(setBingBackground, 3600000);

      document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        try {
          const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
          });
          if (response.ok) { window.location.href = '/'; } 
          else { document.getElementById('error').style.display = 'block'; }
        } catch (err) {
          console.error('登录失败:', err);
          document.getElementById('error').style.display = 'block';
        }
      });
    </script>
  </body>
  </html>`;
}

// Generate file upload page /upload
function generateUploadPage() {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <link rel="shortcut icon" href="https://pan.811520.xyz/2025-02/1739241502-tgfile-favicon.ico" type="image/x-icon">
  <meta name="description" content="Telegram文件存储与分享平台">
  <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件上传</title>
    <style>
      body {
        font-family: Arial, sans-serif; transition: background-image 1s ease-in-out;
        display: flex; justify-content: center; align-items: center; height: 100vh;
        background-size: cover; background-position: center; margin: 0;
      }
      .container {
        max-width: 800px; width: 100%; background: rgba(255, 255, 255, 0.8);
        backdrop-filter: blur(5px); padding: 10px 40px 20px 40px; border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow-y: auto; max-height: 90vh;
      }
      .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
      .upload-area { border: 2px dashed #666; padding: 40px; text-align: center; border-radius: 8px; cursor: pointer; }
      .upload-area.dragover { border-color: #007bff; background: #f0f8ff; }
      .password-area { margin-top: 15px; text-align: center; }
      .password-area input { padding: 8px; width: 50%; border: 1px solid #ccc; border-radius: 4px; }
      .preview-area { margin-top: 20px; }
      .preview-item { display: flex; align-items: center; padding: 10px; border: 1px solid #ddd; margin-bottom: 10px; border-radius: 4px; }
      .preview-item img { max-width: 100px; max-height: 100px; margin-right: 10px; }
      .preview-item .info { flex-grow: 1; }
      .url-area { margin-top: 10px; }
      .url-area textarea { width: 100%; min-height: 100px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; background: rgba(255, 255, 255, 0.5); color: #333; box-sizing: border-box; }
      .admin-link { color: #007bff; text-decoration: none; }
      .admin-link:hover { text-decoration: underline; }
      .button-group { margin-top: 10px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
      .button-container button { margin-right: 10px; padding: 5px 10px; border: none; border-radius: 4px; background: #007bff; color: white; cursor: pointer; }
      .button-container button:hover { background: #0056b3; }
      .copyright { font-size: 12px; color: #888; }
      .progress-bar { height: 20px; background: #eee; border-radius: 10px; margin: 8px 0; overflow: hidden; position: relative; }
      .progress-track { height: 100%; background: #007bff; transition: width 0.3s ease; width: 0; }
      .progress-text { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); color: white; font-size: 12px; text-shadow: 1px 1px 1px #000; }
      .success .progress-track { background: #28a745; }
      .error .progress-track { background: #dc3545; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header"><h1>文件上传</h1><a href="/admin" class="admin-link">进入管理页面</a></div>
      <div class="upload-area" id="uploadArea">
        <p>点击选择 或 拖拽文件到此处</p>
        <input type="file" id="fileInput" multiple style="display: none">
      </div>
      <div class="password-area"><input type="text" id="passwordInput" placeholder="为文件设置访问密码 (可选)"></div>
      <div class="preview-area" id="previewArea"></div>
      <div class="url-area">
        <textarea id="urlArea" readonly placeholder="上传完成后的链接将显示在这里"></textarea>
        <div class="button-group">
          <div class="button-container">
            <button onclick="copyUrls('url')">复制URL</button>
            <button onclick="copyUrls('markdown')">复制Markdown</button>
            <button onclick="copyUrls('html')">复制HTML</button>
          </div>
          <div class="copyright">
            <span>© 2025 by <a href="https://github.com/yutian81/CF-tgfile" target="_blank" style="text-decoration: none; color: inherit;">yutian81</a></span>
          </div>
        </div>
      </div>
    </div>

    <script>
      async function setBingBackground() { /* same as login page */ 
        try {
          const response = await fetch('/bing');
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) { console.error('获取背景图失败:', error); }
      }
      setBingBackground(); 
      setInterval(setBingBackground, 3600000);

      const uploadArea = document.getElementById('uploadArea');
      const fileInput = document.getElementById('fileInput');
      const previewArea = document.getElementById('previewArea');
      const urlArea = document.getElementById('urlArea');
      let uploadedUrls = [];

      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(e => {
        uploadArea.addEventListener(e, p, false); document.body.addEventListener(e, p, false);
      });
      function p(e) { e.preventDefault(); e.stopPropagation(); }
      ['dragenter', 'dragover'].forEach(e => uploadArea.addEventListener(e, () => uploadArea.classList.add('dragover'), false));
      ['dragleave', 'drop'].forEach(e => uploadArea.addEventListener(e, () => uploadArea.classList.remove('dragover'), false));

      uploadArea.addEventListener('drop', e => handleFiles({ target: { files: e.dataTransfer.files } }), false);
      uploadArea.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', handleFiles);
      document.addEventListener('paste', e => {
        for (let item of (e.clipboardData || e.originalEvent.clipboardData).items) {
          if (item.kind === 'file') uploadFile(item.getAsFile());
        }
      });

      async function handleFiles(e) {
        const response = await fetch('/config');
        const config = await response.json();
        for (let file of Array.from(e.target.files)) {
          if (file.size > config.maxSizeMB * 1024 * 1024) {
            alert(\`文件 \${file.name} 超过\${config.maxSizeMB}MB限制\`);
            continue;
          }
          await uploadFile(file);
        }
      }

      async function uploadFile(file) {
        const preview = createPreview(file);
        previewArea.appendChild(preview);
        const xhr = new XMLHttpRequest();
        const progressTrack = preview.querySelector('.progress-track');
        const progressText = preview.querySelector('.progress-text');

        xhr.upload.addEventListener('progress', e => {
          if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            progressTrack.style.width = \`\${percent}%\`;
            progressText.textContent = \`\${percent}%\`;
          }
        });

        xhr.addEventListener('load', () => {
          try {
            const data = JSON.parse(xhr.responseText);
            if (xhr.status >= 200 && xhr.status < 300 && data.status === 1) {
              progressText.textContent = data.msg;
              uploadedUrls.push(data.url);
              updateUrlArea();
              preview.classList.add('success');
            } else {
              progressText.textContent = [data.msg, data.error].filter(Boolean).join(' | ');
              preview.classList.add('error');
            }
          } catch (e) {
            progressText.textContent = '✗ 响应解析失败';
            preview.classList.add('error');
          }
        });

        const password = document.getElementById('passwordInput').value;
        const formData = new FormData();
        formData.append('file', file);
        if (password) formData.append('password', password);
        xhr.open('POST', '/upload');
        xhr.send(formData);
      }

      function createPreview(file) {
        const div = document.createElement('div');
        div.className = 'preview-item';
        if (file.type.startsWith('image/')) {
          const img = document.createElement('img');
          img.src = URL.createObjectURL(file);
          div.appendChild(img);
        }
        const info = document.createElement('div');
        info.className = 'info';
        info.innerHTML = \`<div>\${file.name}</div><div>\${formatSize(file.size)}</div><div class="progress-bar"><div class="progress-track"></div><span class="progress-text">0%</span></div>\`;
        div.appendChild(info);
        return div;
      }

      function formatSize(bytes) { /* same as backend */ 
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return \`\${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} \${units[i]}\`;
      }
      function updateUrlArea() { urlArea.value = uploadedUrls.join('\\n'); }
      function copyUrls(format) {
        let text = '';
        switch (format) {
          case 'url': text = uploadedUrls.join('\\n'); break;
          case 'markdown': text = uploadedUrls.map(url => \`![](\${url})\`).join('\\n'); break;
          case 'html': text = uploadedUrls.map(url => \`<img src="\${url}" />\`).join('\\n'); break;
        }
        navigator.clipboard.writeText(text).then(() => alert('已复制到剪贴板'));
      }
    </script>
  </body>
  </html>`;
}

// Generate file management page /admin
function generateAdminPage(fileCards, qrModal, editModal, totalFiles) {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <link rel="shortcut icon" href="https://pan.811520.xyz/2025-02/1739241502-tgfile-favicon.ico" type="image/x-icon">
  <meta name="description" content="Telegram文件存储与分享平台">
  <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件管理</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-size: cover; background-position: center; transition: background-image 1s ease-in-out; }
      .container { max-width: 1200px; margin: 0 auto; }
      .header { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(5px); padding: 15px 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
      .header-left, .header-right, .bulk-actions { display: flex; align-items: center; gap: 15px; }
      h2 { margin: 0; }
      .file-stats { font-size: 1.2em; font-weight: bold; color: red; }
      .search { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 250px; }
      .backup { color: #007bff; text-decoration: none; }
      .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 20px; }
      .file-card { background: rgba(255, 255, 255, 0.8); border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; position: relative; }
      .file-checkbox { position: absolute; top: 10px; left: 10px; width: 18px; height: 18px; z-index: 1; }
      .file-preview { height: 150px; background: #eee; display: flex; align-items: center; justify-content: center; }
      .file-preview img, .file-preview video { max-width: 100%; max-height: 100%; object-fit: contain; }
      .file-info { padding: 10px; font-size: 14px; word-break: break-all; }
      .file-info > div { margin-bottom: 5px; }
      .password-info { cursor: pointer; color: #6c757d; font-size: 12px; }
      .password-info:hover { color: #007bff; }
      .file-actions { padding: 10px; border-top: 1px solid #eee; display: flex; flex-wrap: wrap; gap: 5px; justify-content: center; }
      .btn { padding: 5px 10px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; text-align: center; }
      .btn-delete { background: #dc3545; color: white; }
      .btn-copy, .btn-down { background: #007bff; color: white; }
      .btn-edit { background: #ffc107; color: black; }
      .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); justify-content: center; align-items: center; }
      .modal-content { background-color: #fefefe; padding: 20px; border-radius: 8px; width: 90%; max-width: 500px; text-align: center; }
      .modal-content .form-group { margin-bottom: 15px; text-align: left; }
      .modal-content .form-group label { display: block; margin-bottom: 5px; }
      .modal-content .form-group input { width: 100%; padding: 8px; box-sizing: border-box; }
      .modal-buttons { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
      .share-link-container { margin-top: 15px; display: flex; align-items: center; justify-content: center; gap: 10px; }
      .share-link-container a { word-break: break-all; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="header-left">
          <h2>文件管理</h2>
          <div class="bulk-actions">
            <label><input type="checkbox" id="selectAllCheckbox"> 全选</label>
            <button id="deleteSelectedBtn" class="btn btn-delete">删除选中</button>
          </div>
        </div>
        <div class="header-right">
          <span class="file-stats">总文件数: ${totalFiles}</span>
          <a href="/upload" class="backup">返回</a>
          <input type="text" class="search" placeholder="搜索文件..." id="searchInput">
        </div>
      </div>
      <div class="grid" id="fileGrid">${fileCards}</div>
      ${qrModal}
      ${editModal}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      async function setBingBackground() { /* same as login page */ 
        try {
          const response = await fetch('/bing');
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) { console.error('获取背景图失败:', error); }
      }
      setBingBackground(); 
      setInterval(setBingBackground, 3600000);

      document.getElementById('selectAllCheckbox').addEventListener('change', e => {
        document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = e.target.checked);
      });

      document.getElementById('deleteSelectedBtn').addEventListener('click', async () => {
        const selectedUrls = Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => cb.value);
        if (selectedUrls.length === 0) return alert('请先选择要删除的文件');
        deleteFiles(selectedUrls);
      });
      
      document.getElementById('searchInput').addEventListener('input', e => {
        const term = e.target.value.toLowerCase();
        document.querySelectorAll('.file-card').forEach(card => {
            const name = card.querySelector('.file-info div:first-child').textContent.toLowerCase();
            card.style.display = name.includes(term) ? '' : 'none';
        });
      });

      async function deleteFiles(urls) {
        if (!confirm(\`确定要删除选中的 \${urls.length} 个文件吗？\`)) return;
        try {
            const response = await fetch('/delete', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls })
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || '删除失败');
            alert(result.message);
            urls.forEach(url => document.querySelector(\`[data-url="\${url}"]\`)?.remove());
        } catch (error) {
            alert('删除失败: ' + error.message);
        }
      }
      
      function deleteSingleFile(url) { deleteFiles([url]); }

      let currentShareUrl = '';
      function showQRCode(url) {
        currentShareUrl = url;
        document.getElementById('shareLink').href = url;
        document.getElementById('shareLink').textContent = url;
        const qrcodeDiv = document.getElementById('qrcode');
        qrcodeDiv.innerHTML = '';
        new QRCode(qrcodeDiv, { text: url, width: 200, height: 200 });
        document.getElementById('qrModal').style.display = 'flex';
      }

      function handleCopyUrl() {
        navigator.clipboard.writeText(currentShareUrl).then(() => {
          const btn = document.getElementById('copyLinkBtn');
          btn.textContent = '✔ 已复制';
          setTimeout(() => { btn.textContent = '复制'; }, 2000);
        });
      }
      
      function openEditModal(url, name, password) {
        document.getElementById('editFileUrl').value = url;
        document.getElementById('editFileName').value = name;
        document.getElementById('editFilePassword').value = password;
        document.getElementById('editModal').style.display = 'flex';
      }

      async function saveFileChanges() {
        const url = document.getElementById('editFileUrl').value;
        const fileName = document.getElementById('editFileName').value;
        const password = document.getElementById('editFilePassword').value;
        try {
            const response = await fetch('/update', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, fileName, password })
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || '更新失败');
            alert('更新成功');
            window.location.reload();
        } catch (error) {
            alert('更新失败: ' + error.message);
        }
      }

      function copyPassword(password, element) {
        navigator.clipboard.writeText(password).then(() => {
          const originalText = element.textContent;
          element.textContent = '✔ 已复制';
          setTimeout(() => { element.textContent = originalText; }, 2000);
        });
      }

      function closeModal(modalId) { document.getElementById(modalId).style.display = 'none'; }
      window.addEventListener('click', e => {
        if (e.target.classList.contains('modal')) e.target.style.display = 'none';
      });
    </script>
  </body>
  </html>`;
}
