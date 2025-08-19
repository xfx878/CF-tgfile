// Due to Telegram's limitations, although files over 20M can be uploaded, a direct link cannot be returned.
// Therefore, the code is modified to prevent uploading files larger than 20MB.

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
      maxSizeMB: Number(env.MAX_SIZE_MB) || 20 // single file upload size defaults to 20M
    };

    // Initialize the database
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
      '/update': () => handleUpdateRequest(request, config), // Add new route for updates
      '/search': () => handleSearchRequest(request, config),
      '/bing': () => handleBingImagesRequest(request, config)
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
  const authToken = cookies.match(/auth_token=([^;]+)/); // Get auth_token from cookies
  if (authToken) {
    try {
      // Decode the token and check for expiration
      const tokenData = JSON.parse(atob(authToken[1]));
      const now = Date.now();           
      // Check if the token has expired
      if (now > tokenData.expiration) {
        console.log("Token has expired");
        return false;
      }          
      // If the token is valid, return whether the username matches
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
    // Use the authenticate function to check if the user is authenticated
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
      // Create token data including username and expiration time
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

// Handle file uploads
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
    const password = formData.get('password') || null; // Get password, default to null if empty

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
      password
    ).run();

    return new Response(
      JSON.stringify({ status: 1, msg: "✔ 上传成功", url }),
      { headers: { 'Content-Type': 'application/json' }}
    );

  } catch (error) {
    console.error(`[Upload Error] ${error.message}`);
    // Set different status codes based on the error message
    let statusCode = 500; // Default 500
    if (error.message.includes(`文件超过${config.maxSizeMB}MB限制`)) {
      statusCode = 400; // Client error: file size exceeded
    } else if (error.message.includes('Telegram参数配置错误')) {
      statusCode = 502; // Gateway error: failed to communicate with Telegram
    } else if (error.message.includes('未获取到文件ID') || error.message.includes('未获取到tg消息ID')) {
      statusCode = 500; // Internal server error: abnormal data returned from Telegram
    } else if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
      statusCode = 504; // Network timeout or disconnection
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

  const { results: fileList = [] } = await config.database.prepare(
    `SELECT url, fileId, message_id, created_at, file_name, file_size, mime_type, password
    FROM files
    ORDER BY created_at DESC`
  ).all();

  const fileCards = fileList.map(file => {
    const fileName = file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const passwordDisplay = file.password ? `<div>密码: <span class="password-text" onclick="copyText('${file.password}', this)">${file.password}</span></div>` : '';
    
    // File preview information and action elements
    return `
      <div class="file-card" data-url="${file.url}">
        <input type="checkbox" class="file-checkbox">
        <div class="file-preview">
          ${getPreviewHtml(file.url)}
        </div>
        <div class="file-info">
          <div class="file-name">${fileName}</div>
          <div>${fileSize}</div>
          <div>${createdAt}</div>
          ${passwordDisplay}
        </div>
        <div class="file-actions">
          <button class="btn btn-edit" onclick="openEditModal('${file.url}', '${fileName}', '${file.password || ''}')">编辑</button>
          <button class="btn btn-copy" onclick="showQRCode('${file.url}')">分享</button>
          <a class="btn btn-down" href="${file.url}" download="${fileName}">下载</a>
        </div>
      </div>
    `;
  }).join('');

  // QR code sharing element
  const qrModal = `
    <div id="qrModal" class="modal">
      <div class="modal-content">
        <span class="close-btn" onclick="closeModal('qrModal')">&times;</span>
        <h2>分享文件</h2>
        <div id="qrcode"></div>
        <div id="share-link-container"></div>
      </div>
    </div>
  `;
  
  // Edit modal element
  const editModal = `
    <div id="editModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal('editModal')">&times;</span>
            <h2>编辑文件信息</h2>
            <form id="editForm">
                <input type="hidden" id="edit-url">
                <div class="form-group">
                    <label for="edit-file-name">文件名:</label>
                    <input type="text" id="edit-file-name" required>
                </div>
                <div class="form-group">
                    <label for="edit-password">访问密码 (留空则无密码):</label>
                    <input type="text" id="edit-password">
                </div>
                <button type="submit" class="btn btn-primary">保存</button>
            </form>
        </div>
    </div>
  `;

  const html = generateAdminPage(fileCards, qrModal, editModal, fileList.length);
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
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
      `SELECT url, fileId, message_id, created_at, file_name, file_size, mime_type, password
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
    return `<img src="${url}" alt="预览" onerror="this.onerror=null;this.src='https://placehold.co/200x150/EEE/31343C?text=Preview';">`;
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
  const url = request.url;
  const cache = caches.default;
  const cacheKey = new Request(url);

  try {
    // Try to get from cache
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      console.log(`[Cache Hit] ${url}`);
      return cachedResponse;
    }

    // Query file from database
    const file = await config.database.prepare(
      `SELECT fileId, message_id, file_name, mime_type, password
      FROM files WHERE url = ?`
    ).bind(url).first();

    if (!file) {
      console.log(`[404] File not found: ${url}`);
      return new Response('文件不存在', { 
        status: 404,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }
    
    // If there is a password, verify it
    if (file.password) {
        if (request.method === 'POST') {
            const formData = await request.formData();
            const submittedPassword = formData.get('password');
            if (submittedPassword === file.password) {
                // Password correct, proceed to serve the file
            } else {
                return new Response(generatePasswordPage(url, '密码错误，请重试。'), {
                    status: 401,
                    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
                });
            }
        } else {
            return new Response(generatePasswordPage(url), {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }


    // Get Telegram file path
    const tgResponse = await fetch(
      `https://api.telegram.org/bot${config.tgBotToken}/getFile?file_id=${file.fileId}`
    );

    if (!tgResponse.ok) {
      console.error(`[Telegram API Error] ${await tgResponse.text()} for file ${file.fileId}`);
      return new Response('获取文件失败', { 
        status: 500,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }

    const tgData = await tgResponse.json();
    const filePath = tgData.result?.file_path;

    if (!filePath) {
      console.error(`[Invalid Path] No file_path in response for ${file.fileId}`);
      return new Response('文件路径无效', { 
        status: 404,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }

    // Download file
    const fileUrl = `https://api.telegram.org/file/bot${config.tgBotToken}/${filePath}`;
    const fileResponse = await fetch(fileUrl);

    if (!fileResponse.ok) {
      console.error(`[Download Error] Failed to download from ${fileUrl}`);
      return new Response('下载文件失败', { 
        status: 500,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }

    // Use stored MIME type or determine from extension
    const contentType = file.mime_type || getContentType(url.split('.').pop().toLowerCase());

    // Create response and cache it
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
    console.log(`[Cache Set] ${url}`);
    return response;

  } catch (error) {
    console.error(`[Error] ${error.message} for ${url}`);
    return new Response('服务器内部错误', { 
      status: 500,
      headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
    });
  }
}

// Handle file deletion
async function handleDeleteRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
  }

  try {
    const { urls } = await request.json();
    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return new Response(JSON.stringify({ error: '无效的URL列表' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    let successes = 0;
    let failures = 0;
    const errors = [];

    for (const url of urls) {
      try {
        const file = await config.database.prepare(
          'SELECT fileId, message_id FROM files WHERE url = ?'
        ).bind(url).first();
        if (!file) {
          failures++;
          errors.push(`文件不存在: ${url}`);
          continue;
        }

        const deleteResponse = await fetch(
          `https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`
        );
        
        // Even if Telegram deletion fails, delete from DB
        await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();

        if (!deleteResponse.ok) {
          const errorData = await deleteResponse.json();
          throw new Error(`Telegram: ${errorData.description}`);
        }
        successes++;
      } catch (e) {
        failures++;
        errors.push(`删除失败 ${url}: ${e.message}`);
        console.error(`[Delete Error] for ${url}: ${e.message}`);
      }
    }

    return new Response(JSON.stringify({
      success: failures === 0,
      message: `成功删除 ${successes} 个文件, 失败 ${failures} 个。`,
      errors: errors
    }), { headers: { 'Content-Type': 'application/json' } });

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(JSON.stringify({ error: '服务器内部错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Handle file info updates
async function handleUpdateRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
    }

    try {
        const { url, fileName, password } = await request.json();
        if (!url || !fileName) {
            return new Response(JSON.stringify({ error: '无效的输入' }), { status: 400 });
        }

        await config.database.prepare(
            `UPDATE files SET file_name = ?, password = ? WHERE url = ?`
        ).bind(fileName, password || null, url).run();

        return new Response(JSON.stringify({ success: true, message: '更新成功' }), {
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        console.error(`[Update Error] ${error.message}`);
        return new Response(JSON.stringify({ error: '服务器内部错误' }), { status: 500 });
    }
}


// Supported upload file types
function getContentType(ext) {
  const types = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/x-icon',
    mp4: 'video/mp4', webm: 'video/webm', mp3: 'audio/mpeg', wav: 'audio/wav',
    ogg: 'audio/ogg', pdf: 'application/pdf', txt: 'text/plain', md: 'text/markdown',
    zip: 'application/zip', rar: 'application/x-rar-compressed', json: 'application/json',
    xml: 'application/xml', ini: 'text/plain', js: 'application/javascript',
    yml: 'application/yaml', yaml: 'application/yaml', py: 'text/x-python',
    sh: 'application/x-sh',
  };
  return types[ext] || 'application/octet-stream';
}

async function handleBingImagesRequest() {
  const cache = caches.default;
  const cacheKey = new Request('https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=5');
  
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
    console.error('Error fetching Bing API:', error);
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

// Login page generation function /login
function generateLoginPage() {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <link rel="shortcut icon" href="https://placehold.co/32x32/007BFF/FFFFFF?text=F" type="image/x-icon">
  <meta name="description" content="Telegram文件存储与分享平台">
  <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录</title>
    <style>
      body {
        display: flex; justify-content: center; align-items: center; height: 100vh;
        background: #f5f5f5; font-family: Arial, sans-serif;
        background-size: cover; background-position: center; transition: background-image 1s ease-in-out;
      }
      .login-container {
        background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px);
        padding: 20px 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        width: 100%; max-width: 400px;
      }
      .form-group { margin-bottom: 1rem; }
      input {
        width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px;
        font-size: 1rem; box-sizing: border-box; background: rgba(255, 255, 255, 0.7); color: #333;
      }
      button {
        width: 100%; padding: 0.75rem; background: #007bff; color: white;
        border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; margin-bottom: 10px;
      }
      button:hover { background: #0056b3; }
      .error { color: #dc3545; margin-top: 1rem; display: none; text-align: center; }
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
        const errorDiv = document.getElementById('error');
        
        try {
          const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
          });
          
          if (response.ok) {
            window.location.href = '/upload';
          } else {
            errorDiv.style.display = 'block';
          }
        } catch (err) {
          console.error('登录失败:', err);
          errorDiv.style.display = 'block';
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
  <link rel="shortcut icon" href="https://placehold.co/32x32/007BFF/FFFFFF?text=F" type="image/x-icon">
  <meta name="description" content="Telegram文件存储与分享平台">
  <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件上传</title>
    <style>
      body {
        font-family: Arial, sans-serif; transition: background-image 1s ease-in-out;
        display: flex; justify-content: center; align-items: center; height: 100vh;
        background: #f5f5f5; margin: 0; background-size: cover; background-position: center;
      }
      .container {
        max-width: 800px; width: 90%; background: rgba(255, 255, 255, 0.8);
        backdrop-filter: blur(10px); padding: 10px 40px 20px 40px; border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow-y: auto; max-height: 90vh;
      }
      .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
      .upload-area {
        border: 2px dashed #666; padding: 40px; text-align: center; margin: 0 auto;
        border-radius: 8px; transition: all 0.3s; box-sizing: border-box; cursor: pointer;
      }
      .upload-area.dragover { border-color: #007bff; background: #f0f8ff; }
      #password-input {
          margin-top: 15px; padding: 10px; width: calc(100% - 22px); border-radius: 4px; border: 1px solid #ccc;
      }
      .preview-area { margin-top: 20px; }
      .preview-item {
        display: flex; align-items: center; padding: 10px; border: 1px solid #ddd;
        margin-bottom: 10px; border-radius: 4px; background: rgba(255,255,255,0.5);
      }
      .preview-item img { max-width: 100px; max-height: 100px; margin-right: 10px; }
      .preview-item .info { flex-grow: 1; }
      .url-area textarea {
        width: 100%; min-height: 100px; padding: 10px; border: 1px solid #ddd;
        border-radius: 4px; background: rgba(255, 255, 255, 0.5); color: #333; box-sizing: border-box;
      }
      .admin-link { color: #007bff; text-decoration: none; }
      .admin-link:hover { text-decoration: underline; }
      .button-group { margin-top: 10px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;}
      .button-container button {
        padding: 5px 10px; border: none; border-radius: 4px; background: #007bff;
        color: white; cursor: pointer;
      }
      .button-container button:hover { background: #0056b3; }
      .copyright { font-size: 12px; color: #555; text-align: right; }
      .progress-bar { height: 20px; background: #eee; border-radius: 10px; margin: 8px 0; overflow: hidden; position: relative; }
      .progress-track { height: 100%; background: #007bff; transition: width 0.3s ease; width: 0; }
      .progress-text { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); color: #333; font-size: 12px; mix-blend-mode: difference; filter: invert(1);}
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
        <input type="text" id="password-input" placeholder="自定义访问密码 (可选)">
      </div>
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
      async function setBingBackground() {
        try {
          const response = await fetch('/bing');
          const data = await response.json();
          if (data.status && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) { console.error('获取背景图失败:', error); }
      }
      setBingBackground();
      setInterval(setBingBackground, 3600000);

      const uploadArea = document.getElementById('uploadArea');
      const fileInput = document.getElementById('fileInput');
      const passwordInput = document.getElementById('password-input');
      const previewArea = document.getElementById('previewArea');
      const urlArea = document.getElementById('urlArea');
      let uploadedUrls = [];

      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, e => { e.preventDefault(); e.stopPropagation(); }, false);
        document.body.addEventListener(eventName, e => { e.preventDefault(); e.stopPropagation(); }, false);
      });
      ['dragenter', 'dragover'].forEach(eventName => uploadArea.addEventListener(eventName, () => uploadArea.classList.add('dragover'), false));
      ['dragleave', 'drop'].forEach(eventName => uploadArea.addEventListener(eventName, () => uploadArea.classList.remove('dragover'), false));

      uploadArea.addEventListener('drop', e => handleFiles(e.dataTransfer.files), false);
      uploadArea.addEventListener('click', (e) => { if(e.target !== passwordInput) fileInput.click(); });
      fileInput.addEventListener('change', e => handleFiles(e.target.files));

      document.addEventListener('paste', async (e) => {
        const items = (e.clipboardData || window.clipboardData).items;
        for (const item of items) {
          if (item.kind === 'file') {
            await uploadFile(item.getAsFile());
          }
        }
      });

      async function handleFiles(files) {
        const response = await fetch('/config');
        const config = await response.json();
        for (const file of files) {
          if (file.size > config.maxSizeMB * 1024 * 1024) {
            alert(\`文件 \${file.name} 超过 \${config.maxSizeMB}MB 限制\`);
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
              const errorMsg = [data.msg, data.error].filter(Boolean).join(' | ');
              progressText.textContent = errorMsg || '上传失败';
              preview.classList.add('error');
            }
          } catch (e) {
            progressText.textContent = '✗ 响应解析失败';
            preview.classList.add('error');
          }
        });
        
        xhr.addEventListener('error', () => {
            progressText.textContent = '✗ 网络错误';
            preview.classList.add('error');
        });

        const formData = new FormData();
        formData.append('file', file);
        formData.append('password', passwordInput.value);
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
        info.innerHTML = \`
          <div>\${file.name}</div>
          <div>\${formatSize(file.size)}</div>
          <div class="progress-bar">
            <div class="progress-track"></div>
            <span class="progress-text">0%</span>
          </div>
        \`;
        div.appendChild(info);
        return div;
      }

      function formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return \`\${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} \${units[i]}\`;
      }

      function updateUrlArea() {
        urlArea.value = uploadedUrls.join('\\n');
      }

      function copyUrls(format) {
        if (uploadedUrls.length === 0) {
            alert('没有可复制的链接');
            return;
        }
        let text = '';
        switch (format) {
          case 'url': text = uploadedUrls.join('\\n'); break;
          case 'markdown': text = uploadedUrls.map(url => \`![](\${url})\`).join('\\n'); break;
          case 'html': text = uploadedUrls.map(url => \`<img src="\${url}" />\`).join('\\n'); break;
        }
        navigator.clipboard.writeText(text).then(() => alert('已复制到剪贴板'), () => alert('复制失败'));
      }
    </script>
  </body>
  </html>`;
}

// Generate file management page /admin
function generateAdminPage(fileCards, qrModal, editModal, fileCount) {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <link rel="shortcut icon" href="https://placehold.co/32x32/007BFF/FFFFFF?text=F" type="image/x-icon">
  <meta name="description" content="Telegram文件存储与分享平台">
  <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件管理</title>
    <style>
      body {
        font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5;
        background-size: cover; background-position: center; transition: background-image 1s ease-in-out;
      }
      .container { max-width: 1200px; margin: 0 auto; }
      .header {
        background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px);
        padding: 20px 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px;
      }
      .header h2 { margin: 0; }
      .header-left, .header-right { display: flex; align-items: center; gap: 15px; flex-wrap: wrap; }
      #file-stats { font-size: 1.2em; font-weight: bold; color: red; }
      #search-input { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 250px; background: rgba(255, 255, 255, 0.5); }
      .btn { padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; color: white; }
      .btn-primary { background-color: #007bff; } .btn-primary:hover { background-color: #0056b3; }
      .btn-danger { background-color: #dc3545; } .btn-danger:hover { background-color: #c82333; }
      .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 20px; }
      .file-card {
        background: rgba(255, 255, 255, 0.8); border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        overflow: hidden; position: relative; display: flex; flex-direction: column;
      }
      .file-preview { height: 150px; background: #eee; display: flex; align-items: center; justify-content: center; }
      .file-preview img, .file-preview video { max-width: 100%; max-height: 100%; object-fit: contain; }
      .file-info { padding: 10px; font-size: 14px; flex-grow: 1; word-wrap: break-word; }
      .file-name { font-weight: bold; margin-bottom: 5px; }
      .password-text { cursor: pointer; background: #eee; padding: 2px 4px; border-radius: 3px; }
      .file-actions { padding: 10px; border-top: 1px solid #eee; display: flex; justify-content: space-around; gap: 5px; }
      .file-actions .btn, .file-actions .btn-down { font-size: 12px; padding: 5px 8px; }
      .btn-edit { background: #ffc107; }
      .btn-copy { background: #17a2b8; }
      .btn-down { background: #28a745; text-decoration: none; color: white; display: inline-block; text-align: center; }
      .file-checkbox { position: absolute; left: 10px; top: 10px; z-index: 10; transform: scale(1.2); }
      .modal {
        display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%;
        overflow: auto; background-color: rgba(0,0,0,0.6); justify-content: center; align-items: center;
      }
      .modal-content {
        background-color: #fefefe; margin: auto; padding: 20px; border: 1px solid #888;
        width: 90%; max-width: 500px; border-radius: 10px; position: relative;
      }
      .close-btn { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
      #qrcode { margin: 20px auto; }
      #share-link-container { display: flex; align-items: center; gap: 10px; margin-top: 15px; justify-content: center; }
      #share-link { color: #007bff; text-decoration: none; }
      #editForm .form-group { margin-bottom: 15px; }
      #editForm label { display: block; margin-bottom: 5px; }
      #editForm input { width: 100%; padding: 8px; box-sizing: border-box; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="header-left">
          <h2>文件管理</h2>
          <span id="file-stats">总计: ${fileCount} 个文件</span>
        </div>
        <div class="header-right">
          <label><input type="checkbox" id="select-all"> 全选</label>
          <button id="delete-selected" class="btn btn-danger">删除选中</button>
          <input type="text" id="search-input" placeholder="搜索文件名...">
          <a href="/upload" class="btn btn-primary">返回上传</a>
        </div>
      </div>
      <div class="grid" id="file-grid">${fileCards}</div>
      ${qrModal}
      ${editModal}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      async function setBingBackground() {
        try {
          const response = await fetch('/bing');
          const data = await response.json();
          if (data.status && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) { console.error('获取背景图失败:', error); }
      }
      setBingBackground();
      setInterval(setBingBackground, 3600000);

      const searchInput = document.getElementById('search-input');
      const fileGrid = document.getElementById('file-grid');
      const selectAllCheckbox = document.getElementById('select-all');
      const deleteSelectedBtn = document.getElementById('delete-selected');

      searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        document.querySelectorAll('.file-card').forEach(card => {
          const fileName = card.querySelector('.file-name').textContent.toLowerCase();
          card.style.display = fileName.includes(searchTerm) ? 'flex' : 'none';
        });
      });
      
      selectAllCheckbox.addEventListener('change', (e) => {
        document.querySelectorAll('.file-checkbox').forEach(checkbox => {
            checkbox.checked = e.target.checked;
        });
      });
      
      deleteSelectedBtn.addEventListener('click', async () => {
        const selectedUrls = Array.from(document.querySelectorAll('.file-checkbox:checked'))
                                  .map(cb => cb.closest('.file-card').dataset.url);
        if (selectedUrls.length === 0) {
            alert('请先选择要删除的文件');
            return;
        }
        if (confirm(\`确定要删除选中的 \${selectedUrls.length} 个文件吗？\`)) {
            try {
                const response = await fetch('/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ urls: selectedUrls })
                });
                const result = await response.json();
                alert(result.message);
                if (result.success || result.errors.length < selectedUrls.length) {
                    location.reload();
                }
            } catch (error) {
                alert('删除失败: ' + error.message);
            }
        }
      });

      let currentShareUrl = '';
      function showQRCode(url) {
        currentShareUrl = url;
        const modal = document.getElementById('qrModal');
        const qrcodeDiv = document.getElementById('qrcode');
        qrcodeDiv.innerHTML = '';
        new QRCode(qrcodeDiv, { text: url, width: 200, height: 200 });
        
        const linkContainer = document.getElementById('share-link-container');
        linkContainer.innerHTML = \`
            <a href="\${url}" id="share-link" target="_blank">\${url}</a>
            <button class="btn btn-primary" onclick="copyText('\${url}')">复制</button>
        \`;
        modal.style.display = 'flex';
      }

      function copyText(text, element = null) {
        navigator.clipboard.writeText(text).then(() => {
            if (element) {
                const originalText = element.textContent;
                element.textContent = '已复制!';
                setTimeout(() => { element.textContent = originalText; }, 2000);
            } else {
                alert('已复制到剪贴板');
            }
        }).catch(err => alert('复制失败'));
      }

      function closeModal(modalId) {
        document.getElementById(modalId).style.display = 'none';
      }
      
      window.onclick = function(event) {
        if (event.target.classList.contains('modal')) {
          event.target.style.display = 'none';
        }
      }
      
      function openEditModal(url, fileName, password) {
        document.getElementById('edit-url').value = url;
        document.getElementById('edit-file-name').value = fileName;
        document.getElementById('edit-password').value = password;
        document.getElementById('editModal').style.display = 'flex';
      }
      
      document.getElementById('editForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('edit-url').value;
        const fileName = document.getElementById('edit-file-name').value;
        const password = document.getElementById('edit-password').value;
        
        try {
            const response = await fetch('/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, fileName, password })
            });
            const result = await response.json();
            alert(result.message);
            if (result.success) {
                location.reload();
            }
        } catch (error) {
            alert('更新失败: ' + error.message);
        }
      });

    </script>
  </body>
  </html>`;
}

function generatePasswordPage(url, error = '') {
    return `<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>需要密码</title>
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; font-family: sans-serif; }
            .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
            input { padding: 10px; margin-top: 10px; border: 1px solid #ccc; border-radius: 4px; width: 200px; }
            button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 10px; }
            button:hover { background: #0056b3; }
            .error { color: red; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>请输入访问密码</h2>
            <form method="POST" action="${url}">
                <input type="password" name="password" required>
                <button type="submit">确认</button>
            </form>
            ${error ? `<p class="error">${error}</p>` : ''}
        </div>
    </body>
    </html>`;
}
