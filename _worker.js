// Due to Telegram's limitations, although files over 20M can be uploaded, a direct link cannot be returned.
// Therefore, the code is modified to prevent uploads of files larger than 20MB.

// Database initialization function
async function initDatabase(config) {
  // Added custom_name and password columns to the table
  await config.database.prepare(`
    CREATE TABLE IF NOT EXISTS files (
      url TEXT PRIMARY KEY,
      fileId TEXT NOT NULL,
      message_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      file_name TEXT,
      custom_name TEXT,
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
      cookie: Number(env.COOKIE) || 7, // Cookie validity defaults to 7 days
      maxSizeMB: Number(env.MAX_SIZE_MB) || 20 // Max single file upload size defaults to 20M
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
      '/update': () => handleUpdateRequest(request, config), // New endpoint for editing
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
  const authToken = cookies.match(/auth_token=([^;]+)/); // Get auth_token from cookies
  if (authToken) {
    try {
      // Decode the token and verify if it has expired
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
    const password = formData.get('password'); // Get password
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
      password || null
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

  const files = await config.database.prepare(
    `SELECT url, fileId, message_id, created_at, file_name, custom_name, file_size, mime_type, password
    FROM files
    ORDER BY created_at DESC`
  ).all();

  const fileList = files.results || [];
  const totalFiles = fileList.length;
  const totalSize = fileList.reduce((acc, file) => acc + (file.file_size || 0), 0);

  const fileCards = fileList.map(file => {
    const displayName = file.custom_name || file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const passwordDisplay = file.password
        ? `<div class="password-info" title="点击复制密码" onclick="copyPassword('${file.password}', this)">密码: ******</div>`
        : '<div class="password-info">无密码</div>';
        
    return `
      <div class="file-card" data-url="${file.url}">
        <input type="checkbox" class="file-checkbox">
        <div class="file-preview">
          ${getPreviewHtml(file.url, file.mime_type)}
        </div>
        <div class="file-info">
          <div class="file-name" title="${displayName}">${displayName}</div>
          <div>${fileSize}</div>
          ${passwordDisplay}
          <div>${createdAt}</div>
        </div>
        <div class="file-actions">
          <button class="btn btn-edit" onclick="openEditModal('${file.url}', '${displayName}', '${file.password || ''}')">编辑</button>
          <button class="btn btn-copy" onclick="showQRCode('${file.url}')">分享</button>
          <a class="btn btn-down" href="${file.url}" download="${displayName}">下载</a>
        </div>
      </div>
    `;
  }).join('');

  const qrModal = `
    <div id="qrModal" class="qr-modal">
      <div class="qr-content">
        <div id="qrcode"></div>
        <div class="qr-buttons">
          <button class="qr-copy" onclick="handleCopyUrl('url')">复制链接</button>
          <button class="qr-copy" onclick="handleCopyUrl('markdown')">Markdown</button>
          <button class="qr-copy" onclick="handleCopyUrl('html')">HTML</button>
          <button class="qr-close" onclick="closeQRModal()">关闭</button>
        </div>
      </div>
    </div>
  `;
  
  const editModal = `
    <div id="editModal" class="modal">
      <div class="modal-content">
        <span class="close-button" onclick="closeEditModal()">&times;</span>
        <h2>编辑文件信息</h2>
        <input type="hidden" id="editFileUrl">
        <div class="form-group">
          <label for="editFileName">文件名:</label>
          <input type="text" id="editFileName">
        </div>
        <div class="form-group">
          <label for="editFilePassword">密码 (留空则无密码):</label>
          <input type="text" id="editFilePassword">
        </div>
        <button onclick="saveFileChanges()">保存</button>
      </div>
    </div>
  `;

  const html = generateAdminPage(fileCards, qrModal, editModal, totalFiles, totalSize);
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
      `SELECT url, fileId, message_id, created_at, file_name, custom_name, file_size, mime_type, password
       FROM files 
       WHERE file_name LIKE ? OR custom_name LIKE ?
       ORDER BY created_at DESC`
    ).bind(searchPattern, searchPattern).all();

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

// Supported preview file types
function getPreviewHtml(url, mimeType) {
    const isImage = mimeType && mimeType.startsWith('image/');
    const isVideo = mimeType && mimeType.startsWith('video/');
    const isAudio = mimeType && mimeType.startsWith('audio/');

    if (isImage) {
        return `<img src="${url}" alt="预览" loading="lazy">`;
    } else if (isVideo) {
        return `<video src="${url}" controls preload="metadata"></video>`;
    } else if (isAudio) {
        return `<audio src="${url}" controls preload="metadata"></audio>`;
    } else {
        return `<div style="font-size: 48px">📄</div>`;
    }
}

// Get file and cache
async function handleFileRequest(request, config) {
    const url = new URL(request.url);
    const dbUrl = url.origin + url.pathname;

    const file = await config.database.prepare(
        `SELECT fileId, message_id, file_name, custom_name, mime_type, password
        FROM files WHERE url = ?`
    ).bind(dbUrl).first();

    if (!file) {
        return new Response('文件不存在', { status: 404 });
    }

    if (file.password) {
        const providedPassword = url.searchParams.get('password');
        if (request.method === 'POST') {
            const formData = await request.formData();
            if (formData.get('password') === file.password) {
                return serveFile(request, config, file);
            }
        }
        if (providedPassword !== file.password) {
            return new Response(generatePasswordPromptPage(url.pathname), {
                status: 403,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }
    return serveFile(request, config, file);
}

async function serveFile(request, config, file) {
    const url = new URL(request.url);
    const cache = caches.default;
    const cacheKey = new Request(url.toString(), request);

    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) return cachedResponse;

    const tgResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/getFile?file_id=${file.fileId}`);
    if (!tgResponse.ok) return new Response('获取文件失败', { status: 500 });

    const tgData = await tgResponse.json();
    const filePath = tgData.result?.file_path;
    if (!filePath) return new Response('文件路径无效', { status: 404 });

    const fileUrl = `https://api.telegram.org/file/bot${config.tgBotToken}/${filePath}`;
    const fileResponse = await fetch(fileUrl);
    if (!fileResponse.ok) return new Response('下载文件失败', { status: 500 });

    const response = new Response(fileResponse.body, {
        headers: {
            'Content-Type': file.mime_type || 'application/octet-stream',
            'Cache-Control': 'public, max-age=31536000',
            'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(file.custom_name || file.file_name || '')}`
        }
    });

    await cache.put(cacheKey, response.clone());
    return response;
}


// Handle file deletion
async function handleDeleteRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
  }

  try {
    const { urls } = await request.json();
    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return new Response(JSON.stringify({ error: '无效的URL列表' }), { status: 400 });
    }

    for (const url of urls) {
        const file = await config.database.prepare(
          'SELECT message_id FROM files WHERE url = ?'
        ).bind(url).first();
        
        if (file) {
            try {
                await fetch(`https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`);
            } catch (e) {
                console.error("Failed to delete from TG, proceeding to delete from DB:", e.message);
            }
            await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
            const cache = caches.default;
            await cache.delete(new Request(url));
        }
    }
    
    return new Response(JSON.stringify({ success: true, message: '删除成功' }), {
        headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(JSON.stringify({ error: '删除失败' }), { status: 500 });
  }
}

// Handle file info update
async function handleUpdateRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
    }
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: '方法不允许' }), { status: 405 });
    }

    try {
        const { url, custom_name, password } = await request.json();
        await config.database.prepare(
            'UPDATE files SET custom_name = ?, password = ? WHERE url = ?'
        ).bind(custom_name, password || null, url).run();

        return new Response(JSON.stringify({ success: true, message: '更新成功' }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error(`[Update Error] ${error.message}`);
        return new Response(JSON.stringify({ error: '更新失败' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
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
  };
  return types[ext] || 'application/octet-stream';
}

async function handleBingImagesRequest(request) {
    const cache = caches.default;
    const cacheKey = new Request('https://bing.img.run/rand.php');
    
    let response = await cache.match(cacheKey);
    if (!response) {
        const bingResponse = await fetch(cacheKey, { redirect: 'follow' });
        if (bingResponse.ok && bingResponse.url) {
            const data = { status: true, data: [{ url: bingResponse.url }] };
            response = new Response(JSON.stringify(data), {
                headers: {
                    'Content-Type': 'application/json',
                    'Cache-Control': 'public, max-age=3600' // Cache for 1 hour
                }
            });
            await cache.put(cacheKey, response.clone());
        } else {
            return new Response(JSON.stringify({ status: false, message: "获取Bing图片失败" }), { status: 500 });
        }
    }
    return response;
}

// File size calculation function
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${units[i]}`;
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
      body { display: flex; justify-content: center; align-items: center; height: 100vh; background-size: cover; background-position: center; font-family: Arial, sans-serif; transition: background-image 1s ease-in-out; }
      .login-container { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }
      .form-group { margin-bottom: 1.5rem; }
      input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; box-sizing: border-box; }
      button { width: 100%; padding: 0.75rem; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; transition: background 0.3s; }
      button:hover { background: #0056b3; }
      .error { color: #dc3545; margin-top: 1rem; text-align: center; display: none; }
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
            document.body.style.backgroundImage = \`url(\${data.data[0].url})\`;
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
          if (response.ok) {
            window.location.href = '/upload';
          } else {
            document.getElementById('error').style.display = 'block';
          }
        } catch (err) {
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
      body { font-family: Arial, sans-serif; transition: background-image 1s ease-in-out; display: flex; justify-content: center; align-items: center; height: 100vh; background-size: cover; background-position: center; margin: 0; }
      .container { max-width: 800px; width: 90%; background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 20px 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); overflow-y: auto; max-height: 90vh; }
      .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
      .upload-area { border: 2px dashed #007bff; padding: 40px; text-align: center; border-radius: 8px; cursor: pointer; transition: all 0.3s; }
      .upload-area.dragover { border-color: #0056b3; background: rgba(0, 123, 255, 0.1); }
      #filePassword { width: 100%; padding: 10px; margin-top: 15px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
      .preview-area { margin-top: 20px; }
      .preview-item { display: flex; align-items: center; padding: 10px; border: 1px solid #ddd; margin-bottom: 10px; border-radius: 4px; background: rgba(255,255,255,0.5); }
      .preview-item img { max-width: 80px; max-height: 80px; margin-right: 15px; border-radius: 4px; }
      .preview-item .info { flex-grow: 1; }
      .url-area textarea { width: 100%; min-height: 100px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; margin-top: 20px; }
      .button-group { margin-top: 10px; display: flex; justify-content: space-between; align-items: center; }
      .button-container button { margin-right: 10px; padding: 8px 15px; border: none; border-radius: 4px; background: #007bff; color: white; cursor: pointer; }
      .progress-bar { height: 10px; background: #eee; border-radius: 5px; margin-top: 5px; overflow: hidden; }
      .progress-track { height: 100%; background: #007bff; transition: width 0.3s ease; width: 0; }
      .progress-text { font-size: 12px; color: #333; }
      .success .progress-track { background: #28a745; }
      .error .progress-track { background: #dc3545; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header"><h1>文件上传</h1><a href="/admin">进入管理页面</a></div>
      <div class="upload-area" id="uploadArea">
        <p>点击选择 或 拖拽文件到此处</p>
        <input type="file" id="fileInput" multiple style="display: none">
      </div>
      <input type="password" id="filePassword" placeholder="为链接设置访问密码 (可选)">
      <div class="preview-area" id="previewArea"></div>
      <div class="url-area">
        <textarea id="urlArea" readonly placeholder="上传完成后的链接将显示在这里"></textarea>
        <div class="button-group">
          <div class="button-container">
            <button onclick="copyUrls('url')">复制URL</button>
            <button onclick="copyUrls('markdown')">Markdown</button>
            <button onclick="copyUrls('html')">HTML</button>
          </div>
        </div>
      </div>
    </div>
    <script>
      async function setBingBackground() { try { const r = await fetch('/bing'); const d = await r.json(); if (d.status && d.data.length > 0) document.body.style.backgroundImage = \`url(\${d.data[0].url})\`; } catch (e) { console.error(e); } }
      setBingBackground(); setInterval(setBingBackground, 3600000);
      const uploadArea = document.getElementById('uploadArea'), fileInput = document.getElementById('fileInput'), previewArea = document.getElementById('previewArea'), urlArea = document.getElementById('urlArea');
      let uploadedUrls = [];
      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(e => { uploadArea.addEventListener(e, p, false); document.body.addEventListener(e, p, false); });
      function p(e) { e.preventDefault(); e.stopPropagation(); }
      ['dragenter', 'dragover'].forEach(e => uploadArea.addEventListener(e, () => uploadArea.classList.add('dragover'), false));
      ['dragleave', 'drop'].forEach(e => uploadArea.addEventListener(e, () => uploadArea.classList.remove('dragover'), false));
      uploadArea.addEventListener('drop', e => handleFiles({ target: { files: e.dataTransfer.files } }), false);
      uploadArea.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', handleFiles);
      document.addEventListener('paste', async e => { for (let item of (e.clipboardData || e.originalEvent.clipboardData).items) { if (item.kind === 'file') await uploadFile(item.getAsFile()); } });

      async function handleFiles(e) {
        const config = await (await fetch('/config')).json();
        for (let file of Array.from(e.target.files)) {
          if (file.size > config.maxSizeMB * 1024 * 1024) { alert(\`文件 \${file.name} 超过\${config.maxSizeMB}MB限制\`); continue; }
          await uploadFile(file);
        }
      }
      async function uploadFile(file) {
        const preview = createPreview(file);
        previewArea.appendChild(preview);
        const xhr = new XMLHttpRequest(), progressTrack = preview.querySelector('.progress-track'), progressText = preview.querySelector('.progress-text');
        xhr.upload.addEventListener('progress', e => { if (e.lengthComputable) { const p = Math.round((e.loaded / e.total) * 100); progressTrack.style.width = \`\${p}%\`; progressText.textContent = \`上传中... \${p}%\`; } });
        xhr.addEventListener('load', () => {
          try {
            const data = JSON.parse(xhr.responseText);
            if (xhr.status >= 200 && xhr.status < 300 && data.status === 1) {
              progressText.textContent = data.msg; uploadedUrls.push(data.url); urlArea.value = uploadedUrls.join('\\n'); preview.classList.add('success');
            } else {
              progressText.textContent = [data.msg, data.error].filter(Boolean).join(' | '); preview.classList.add('error');
            }
          } catch (e) { progressText.textContent = '✗ 响应解析失败'; preview.classList.add('error'); }
        });
        const formData = new FormData();
        formData.append('file', file);
        const password = document.getElementById('filePassword').value;
        if (password) formData.append('password', password);
        xhr.open('POST', '/upload'); xhr.send(formData);
      }
      function createPreview(file) {
        const div = document.createElement('div'); div.className = 'preview-item';
        if (file.type.startsWith('image/')) { const img = document.createElement('img'); img.src = URL.createObjectURL(file); div.appendChild(img); }
        const info = document.createElement('div'); info.className = 'info';
        info.innerHTML = \`<div>\${file.name} (\${formatSize(file.size)})</div><div class="progress-bar"><div class="progress-track"></div></div><div class="progress-text">准备上传...</div>\`;
        div.appendChild(info); return div;
      }
      function formatSize(b) { const u = ['B', 'KB', 'MB', 'GB']; let s = b, i = 0; while (s >= 1024 && i < 3) { s /= 1024; i++; } return \`\${s.toFixed(2)} \${u[i]}\`; }
      function copyUrls(f) { let t = ''; switch (f) { case 'url': t = uploadedUrls.join('\\n'); break; case 'markdown': t = uploadedUrls.map(u => \`![](\${u})\`).join('\\n'); break; case 'html': t = uploadedUrls.map(u => \`<img src="\${u}" />\`).join('\\n'); break; } navigator.clipboard.writeText(t).then(() => alert('已复制到剪贴板')); }
    </script>
  </body>
  </html>`;
}

// Generate file management page /admin
function generateAdminPage(fileCards, qrModal, editModal, totalFiles, totalSize) {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <link rel="shortcut icon" href="https://pan.811520.xyz/2025-02/1739241502-tgfile-favicon.ico" type="image/x-icon">
  <meta name="description" content="Telegram文件存储与分享平台">
  <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件管理</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-size: cover; background-position: center; background-attachment: fixed; transition: background-image 1s ease-in-out; }
      .container { max-width: 1400px; margin: 0 auto; }
      .header { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 20px 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }
      .header h2, .header .stats { margin-right: 20px; }
      .stats-text { color: red; font-weight: bold; font-size: 1.2em; }
      .header .right-content { display: flex; align-items: center; gap: 15px; }
      .search { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 250px; }
      .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 20px; }
      .file-card { background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(5px); border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; position: relative; display: flex; flex-direction: column; }
      .file-preview { height: 150px; display: flex; align-items: center; justify-content: center; background: #f0f0f0; }
      .file-preview img, .file-preview video { max-width: 100%; max-height: 100%; object-fit: contain; }
      .file-info { padding: 10px; font-size: 13px; flex-grow: 1; }
      .file-info > div { margin-bottom: 5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .password-info { cursor: pointer; }
      .file-actions { padding: 10px; border-top: 1px solid #eee; display: flex; justify-content: space-around; }
      .file-checkbox { position: absolute; left: 10px; top: 10px; z-index: 10; transform: scale(1.2); }
      .btn { padding: 5px 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
      .btn-edit { background: #ffc107; color: black; } .btn-delete { background: #dc3545; color: white; } .btn-copy, .btn-down { background: #007bff; color: white; text-decoration: none; }
      .modal { display: none; position: fixed; z-index: 1001; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.6); justify-content: center; align-items: center; }
      .modal-content { background-color: #fefefe; margin: auto; padding: 20px; border: 1px solid #888; width: 80%; max-width: 500px; border-radius: 8px; }
      .qr-modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); justify-content: center; align-items: center; z-index: 1000; }
      .qr-content { background: white; padding: 20px; border-radius: 10px; text-align: center; }
      #qrcode { margin: 15px 0; }
      .qr-buttons button { margin: 0 5px; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h2>文件管理</h2>
        <div class="stats">
          文件总数: <span class="stats-text">${totalFiles}</span> |
          总大小: <span class="stats-text">${formatSize(totalSize)}</span>
        </div>
        <div class="right-content">
          <button id="selectAllBtn">全选</button>
          <button id="deleteSelectedBtn" class="btn-delete">删除选中</button>
          <input type="text" class="search" placeholder="搜索文件..." id="searchInput">
          <a href="/upload">返回上传</a>
        </div>
      </div>
      <div class="grid" id="fileGrid">${fileCards}</div>
      ${qrModal}
      ${editModal}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      async function setBingBackground() { try { const r = await fetch('/bing'); const d = await r.json(); if (d.status && d.data.length > 0) document.body.style.backgroundImage = \`url(\${d.data[0].url})\`; } catch (e) { console.error(e); } }
      setBingBackground(); setInterval(setBingBackground, 3600000);

      const searchInput = document.getElementById('searchInput');
      const fileGrid = document.getElementById('fileGrid');
      
      searchInput.addEventListener('input', e => {
        const term = e.target.value.toLowerCase();
        document.querySelectorAll('.file-card').forEach(card => {
          const name = card.querySelector('.file-name').textContent.toLowerCase();
          card.style.display = name.includes(term) ? '' : 'none';
        });
      });

      let currentShareUrl = '';
      function showQRCode(url) {
        currentShareUrl = url;
        const modal = document.getElementById('qrModal');
        document.getElementById('qrcode').innerHTML = '';
        new QRCode(document.getElementById('qrcode'), { text: url, width: 200, height: 200 });
        modal.style.display = 'flex';
      }
      function handleCopyUrl(format) {
        let text = '';
        switch(format) {
            case 'url': text = currentShareUrl; break;
            case 'markdown': text = \`![](\${currentShareUrl})\`; break;
            case 'html': text = \`<img src="\${currentShareUrl}" />\`; break;
        }
        navigator.clipboard.writeText(text).then(() => alert('已复制到剪贴板'));
      }
      function closeQRModal() { document.getElementById('qrModal').style.display = 'none'; }

      function openEditModal(url, name, password) {
        document.getElementById('editFileUrl').value = url;
        document.getElementById('editFileName').value = name;
        document.getElementById('editFilePassword').value = password;
        document.getElementById('editModal').style.display = 'flex';
      }
      function closeEditModal() { document.getElementById('editModal').style.display = 'none'; }
      async function saveFileChanges() {
        const url = document.getElementById('editFileUrl').value;
        const custom_name = document.getElementById('editFileName').value;
        const password = document.getElementById('editFilePassword').value;
        const res = await fetch('/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, custom_name, password })
        });
        if (res.ok) { alert('更新成功'); location.reload(); } else { alert('更新失败'); }
        closeEditModal();
      }

      function copyPassword(password, element) {
        navigator.clipboard.writeText(password).then(() => {
            const originalText = element.innerHTML;
            element.innerHTML = '✔ 已复制!';
            setTimeout(() => { element.innerHTML = originalText; }, 2000);
        });
      }

      document.getElementById('selectAllBtn').addEventListener('click', () => {
        const checkboxes = document.querySelectorAll('.file-checkbox');
        const allChecked = Array.from(checkboxes).every(cb => cb.checked);
        checkboxes.forEach(cb => cb.checked = !allChecked);
      });
      
      document.getElementById('deleteSelectedBtn').addEventListener('click', async () => {
        const selected = Array.from(document.querySelectorAll('.file-checkbox:checked'))
                              .map(cb => cb.closest('.file-card').dataset.url);
        if (selected.length === 0) return alert('请先选择文件');
        if (!confirm(\`确定要删除选中的 \${selected.length} 个文件吗？\`)) return;
        
        const res = await fetch('/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls: selected })
        });
        if (res.ok) { alert('删除成功'); location.reload(); } else { alert('删除失败'); }
      });
      
      window.onclick = function(event) {
        if (event.target.classList.contains('modal') || event.target.classList.contains('qr-modal')) {
            event.target.style.display = 'none';
        }
      }
    </script>
  </body>
  </html>`;
}

function generatePasswordPromptPage(path) {
    return `<!DOCTYPE html>
    <html>
    <head>
        <title>需要密码</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; font-family: sans-serif; background: #f0f2f5; }
            .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
            input { padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; width: 200px; }
            button { padding: 10px 20px; border: none; background: #007bff; color: white; border-radius: 4px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>此内容受密码保护</h2>
            <p>请输入密码访问</p>
            <form method="POST" action="${path}">
                <input type="password" name="password" required>
                <button type="submit">提交</button>
            </form>
        </div>
    </body>
    </html>`;
}
