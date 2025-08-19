// The limitation of TG is that although files over 20M can be uploaded, a direct link address cannot be returned.
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
      cookie: Number(env.COOKIE) || 7, // Cookie validity defaults to 7 days
      maxSizeMB: Number(env.MAX_SIZE_MB) || 20 // Single file upload size defaults to 20M
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
      '/bing': handleBingImagesRequest
    };
    const handler = routes[pathname];
    if (handler) {
      return await handler();
    }
    // Handle file access requests
    return await handleFileRequest(request, config);
  }
};

// Handle identity authentication
function authenticate(request, config) {
  const cookies = request.headers.get("Cookie") || "";
  const authToken = cookies.match(/auth_token=([^;]+)/); // Get auth_token from cookie
  if (authToken) {
    try {
      // Decode the token and verify if it's expired
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
  // If authentication is not enabled, redirect directly to the upload page
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
      return new Response("Login successful", {
        status: 200,
        headers: {
          "Set-Cookie": cookie,
          "Content-Type": "text/plain"
        }
      });
    }
    return new Response("Authentication failed", { status: 401 });
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
    const password = formData.get('password'); // Get custom password
    if (!file) throw new Error('File not found');
    if (file.size > config.maxSizeMB * 1024 * 1024) throw new Error(`File exceeds ${config.maxSizeMB}MB limit`);
    
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
    if (!tgResponse.ok) throw new Error('Telegram parameter configuration error');  

    const tgData = await tgResponse.json();
    const result = tgData.result;
    const messageId = tgData.result?.message_id;
    const fileId = result?.document?.file_id ||
                   result?.video?.file_id ||
                   result?.audio?.file_id ||
                  (result?.photo && result.photo[result.photo.length-1]?.file_id);
    if (!fileId) throw new Error('Failed to get file ID');
    if (!messageId) throw new Error('Failed to get TG message ID');

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
      password || null // Store password, null if not provided
    ).run();

    return new Response(
      JSON.stringify({ status: 1, msg: "✔ Upload successful", url }),
      { headers: { 'Content-Type': 'application/json' }}
    );

  } catch (error) {
    console.error(`[Upload Error] ${error.message}`);
    let statusCode = 500;
    if (error.message.includes(`File exceeds ${config.maxSizeMB}MB limit`)) {
      statusCode = 400;
    } else if (error.message.includes('Telegram parameter configuration error')) {
      statusCode = 502;
    } else if (error.message.includes('Failed to get file ID') || error.message.includes('Failed to get TG message ID')) {
      statusCode = 500;
    } else if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
      statusCode = 504;
    }
    return new Response(
      JSON.stringify({ status: 0, msg: "✘ Upload failed", error: error.message }),
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
    `SELECT url, fileId, message_id, created_at, file_name, file_size, mime_type, password
    FROM files
    ORDER BY created_at DESC`
  ).all();

  const fileList = files.results || [];
  const totalFiles = fileList.length; // Get total number of files
  const fileCards = fileList.map(file => {
    const fileName = file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const filePassword = file.password || ''; // Get password
    return `
      <div class="file-card" data-url="${file.url}" data-name="${fileName}" data-password="${filePassword}">
        <input type="checkbox" class="file-checkbox">
        <div class="file-preview">
          ${getPreviewHtml(file.url)}
        </div>
        <div class="file-info">
          <div>${fileName}</div>
          <div>${fileSize}</div>
          <div>${createdAt}</div>
        </div>
        <div class="file-actions">
          <button class="btn btn-share" onclick="showQRCode('${file.url}')">分享</button>
          <button class="btn btn-edit" onclick="openEditModal('${file.url}', '${fileName}', '${filePassword}')">编辑</button>
          <a class="btn btn-down" href="${file.url}" download="${fileName}">下载</a>
        </div>
      </div>
    `;
  }).join('');

  // QR code sharing element
  const qrModal = `
    <div id="qrModal" class="modal">
      <div class="modal-content">
        <div id="qrcode"></div>
        <div class="qr-link-container">
            <a id="qrLink" href="#" target="_blank"></a>
            <button class="btn-copy" onclick="handleCopyUrl()">复制</button>
        </div>
        <button class="modal-close" onclick="closeModal('qrModal')">关闭</button>
      </div>
    </div>
  `;

  // Edit modal element
  const editModal = `
    <div id="editModal" class="modal">
      <div class="modal-content">
        <h3>编辑文件信息</h3>
        <form id="editForm">
            <input type="hidden" id="editFileUrl">
            <div class="form-group">
                <label for="editFileName">文件名:</label>
                <input type="text" id="editFileName" required>
            </div>
            <div class="form-group">
                <label for="editFilePassword">访问密码 (留空则无密码):</label>
                <input type="password" id="editFilePassword">
            </div>
            <div class="modal-buttons">
                <button type="submit" class="btn-submit">保存</button>
                <button type="button" class="modal-close" onclick="closeModal('editModal')">取消</button>
            </div>
        </form>
      </div>
    </div>
  `;

  const html = generateAdminPage(fileCards, qrModal, editModal, totalFiles);
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

// Supported preview file types
function getPreviewHtml(url) {
  const ext = (url.split('.').pop() || '').toLowerCase();
  const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'].includes(ext);
  const isVideo = ['mp4', 'webm'].includes(ext);
  const isAudio = ['mp3', 'wav', 'ogg'].includes(ext);

  if (isImage) {
    return `<img src="${url}" alt="预览" loading="lazy">`;
  } else if (isVideo) {
    return `<video src="${url}" controls muted preload="metadata"></video>`;
  } else if (isAudio) {
    return `<audio src="${url}" controls preload="metadata"></audio>`;
  } else {
    return `<div style="font-size: 48px">📄</div>`;
  }
}

// Get file and cache
async function handleFileRequest(request, config) {
    const url = new URL(request.url);
    const cache = caches.default;
    const cacheKey = new Request(url.toString(), request);

    try {
        const cachedResponse = await cache.match(cacheKey);
        if (cachedResponse) {
            console.log(`[Cache Hit] ${url.toString()}`);
            return cachedResponse;
        }

        const file = await config.database.prepare(
            `SELECT fileId, message_id, file_name, mime_type, password
            FROM files WHERE url = ?`
        ).bind(url.origin + url.pathname).first();

        if (!file) {
            return new Response('文件不存在', { status: 404 });
        }

        // Check for password protection
        if (file.password) {
            if (request.method === 'POST') {
                const formData = await request.formData();
                const submittedPassword = formData.get('password');
                if (submittedPassword === file.password) {
                    // Password correct, proceed to serve file
                } else {
                    return new Response(generatePasswordPrompt("密码错误，请重试。"), {
                        status: 401,
                        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
                    });
                }
            } else {
                return new Response(generatePasswordPrompt(), {
                    status: 200,
                    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
                });
            }
        }

        const tgResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/getFile?file_id=${file.fileId}`);
        if (!tgResponse.ok) {
            return new Response('获取文件失败', { status: 500 });
        }

        const tgData = await tgResponse.json();
        const filePath = tgData.result?.file_path;
        if (!filePath) {
            return new Response('文件路径无效', { status: 404 });
        }

        const fileUrl = `https://api.telegram.org/file/bot${config.tgBotToken}/${filePath}`;
        const fileResponse = await fetch(fileUrl);
        if (!fileResponse.ok) {
            return new Response('下载文件失败', { status: 500 });
        }

        const contentType = file.mime_type || getContentType(url.pathname.split('.').pop().toLowerCase());
        const response = new Response(fileResponse.body, {
            headers: {
                'Content-Type': contentType,
                'Cache-Control': 'public, max-age=31536000',
                'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(file.file_name || '')}`
            }
        });

        await cache.put(cacheKey, response.clone());
        return response;

    } catch (error) {
        console.error(`[Error] ${error.message} for ${url.toString()}`);
        return new Response('服务器内部错误', { status: 500 });
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
      return new Response(JSON.stringify({ error: '无效的URL列表' }), { status: 400 });
    }

    const results = [];
    for (const url of urls) {
      const file = await config.database.prepare(
        'SELECT fileId, message_id FROM files WHERE url = ?'
      ).bind(url).first();
      
      if (!file) {
        results.push({ url, success: false, message: '文件不存在' });
        continue;
      }

      let deleteError = null;
      try {
        const deleteResponse = await fetch(
          `https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`
        );
        if (!deleteResponse.ok) {
          const errorData = await deleteResponse.json();
          throw new Error(errorData.description || 'Telegram API error');
        }
      } catch (error) {
        deleteError = error.message;
      }

      await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
      
      if (deleteError) {
        results.push({ url, success: true, message: `已从数据库删除，但TG消息删除失败: ${deleteError}` });
      } else {
        results.push({ url, success: true, message: '文件删除成功' });
      }
    }
    
    return new Response(JSON.stringify({ results }), { headers: { 'Content-Type': 'application/json' }});

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
}

// Handle file information update
async function handleUpdateRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
    }

    try {
        const { url, newName, newPassword } = await request.json();
        if (!url || !newName) {
            return new Response(JSON.stringify({ error: '缺少必要参数' }), { status: 400 });
        }

        const result = await config.database.prepare(
            'UPDATE files SET file_name = ?, password = ? WHERE url = ?'
        ).bind(newName, newPassword || null, url).run();

        if (result.changes > 0) {
            return new Response(JSON.stringify({ success: true, message: '更新成功' }), {
                headers: { 'Content-Type': 'application/json' }
            });
        } else {
            return new Response(JSON.stringify({ error: '文件不存在或没有变化' }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    } catch (error) {
        console.error(`[Update Error] ${error.message}`);
        return new Response(JSON.stringify({ error: '服务器内部错误' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}


// Supported upload file types
function getContentType(ext) {
  const types = {
    'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png', 'gif': 'image/gif',
    'webp': 'image/webp', 'svg': 'image/svg+xml', 'ico': 'image/x-icon', 'mp4': 'video/mp4',
    'webm': 'video/webm', 'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'ogg': 'audio/ogg',
    'pdf': 'application/pdf', 'txt': 'text/plain', 'md': 'text/markdown', 'zip': 'application/zip',
    'rar': 'application/x-rar-compressed', 'json': 'application/json', 'xml': 'application/xml',
    'js': 'application/javascript', 'css': 'text/css', 'html': 'text/html', 'sh': 'application/x-sh',
    'py': 'text/x-python', 'java': 'text/x-java-source', 'c': 'text/x-c', 'cpp': 'text/x-c++',
    'go': 'text/x-go', 'rs': 'text/rust', 'rb': 'text/x-ruby', 'php': 'application/x-httpd-php',
    'ps1': 'application/powershell', 'bat': 'application/x-bat', 'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt': 'application/vnd.ms-powerpoint',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '7z': 'application/x-7z-compressed', 'tar': 'application/x-tar', 'gz': 'application/gzip',
    'bz2': 'application/x-bzip2', 'xz': 'application/x-xz'
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
      return new Response('Failed to request Bing API', { status: res.status });
    }
    
    const bingData = await res.json();
    const images = bingData.images.map(image => ({ url: `https://cn.bing.com${image.url}` }));
    const returnData = { status: true, message: "Operation successful", data: images };
    
    const response = new Response(JSON.stringify(returnData), { 
      status: 200, 
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=21600',
        'Access-Control-Allow-Origin': '*' 
      }
    });
    
    await cache.put(cacheKey, response.clone());
    return response;
  } catch (error) {
    return new Response('Failed to request Bing API', { status: 500 });
  }
}

// File size calculation function
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${units[i]}`;
}

// Generate password prompt page
function generatePasswordPrompt(errorMessage = "") {
    return `<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>需要密码</title>
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; font-family: sans-serif; background: #f0f2f5; }
            .container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
            input { padding: 0.5rem; margin-top: 1rem; border: 1px solid #ccc; border-radius: 4px; }
            button { padding: 0.5rem 1rem; margin-left: 0.5rem; border: none; background: #007bff; color: white; border-radius: 4px; cursor: pointer; }
            .error { color: red; margin-top: 1rem; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>此文件受密码保护</h2>
            <form method="POST">
                <input type="password" name="password" placeholder="请输入密码" required>
                <button type="submit">提交</button>
            </form>
            ${errorMessage ? `<p class="error">${errorMessage}</p>` : ''}
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
      body { display: flex; justify-content: center; align-items: center; height: 100vh; background: #f5f5f5; font-family: Arial, sans-serif; background-size: cover; background-position: center; transition: background-image 1s ease-in-out; }
      .login-container { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(5px); padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
      .form-group { margin-bottom: 1rem; }
      input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; box-sizing: border-box; background: rgba(255, 255, 255, 0.7); color: #333; }
      button { width: 100%; padding: 0.75rem; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; margin-bottom: 10px; }
      button:hover { background: #0056b3; }
      .error { color: #dc3545; margin-top: 1rem; display: none; }
    </style>
  </head>
  <body>
    <div class="login-container">
      <h2 style="text-align: center; margin-bottom: 2rem;">登录</h2>
      <form id="loginForm">
        <div class="form-group">
          <input type="text" id="username" placeholder="用户名" required>
        </div>
        <div class="form-group">
          <input type="password" id="password" placeholder="密码" required>
        </div>
        <button type="submit">登录</button>
        <div id="error" class="error">用户名或密码错误</div>
      </form>
    </div>
    <script>
      async function setBingBackground() { try { const response = await fetch('/bing'); const data = await response.json(); if (data.status && data.data.length > 0) { const randomIndex = Math.floor(Math.random() * data.data.length); document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`; } } catch (error) { console.error('获取背景图失败:', error); } }
      setBingBackground(); 
      setInterval(setBingBackground, 3600000);
      document.getElementById('loginForm').addEventListener('submit', async (e) => { e.preventDefault(); const username = document.getElementById('username').value; const password = document.getElementById('password').value; try { const response = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) }); if (response.ok) { window.location.href = '/upload'; } else { document.getElementById('error').style.display = 'block'; } } catch (err) { document.getElementById('error').style.display = 'block'; } });
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
      body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f5f5f5; margin: 0; background-size: cover; background-position: center; transition: background-image 1s ease-in-out; }
      .container { max-width: 800px; width: 100%; background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(5px); padding: 10px 40px 20px 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow-y: auto; max-height: 90vh; }
      .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
      .upload-area { border: 2px dashed #666; padding: 20px; text-align: center; border-radius: 8px; transition: all 0.3s; }
      .upload-area.dragover { border-color: #007bff; background: #f0f8ff; }
      #password-input { margin-top: 15px; width: calc(100% - 20px); padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
      .preview-area { margin-top: 20px; }
      .preview-item { display: flex; align-items: center; padding: 10px; border-bottom: 1px solid #eee; }
      .preview-item img { max-width: 50px; max-height: 50px; margin-right: 10px; border-radius: 4px; }
      .preview-item .info { flex-grow: 1; }
      .url-area textarea { width: 100%; min-height: 100px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; background: rgba(255, 255, 255, 0.5); color: #333; box-sizing: border-box; }
      .admin-link { color: #007bff; text-decoration: none; }
      .button-group { margin-top: 10px; display: flex; justify-content: space-between; align-items: center; }
      .button-container button { margin-right: 10px; padding: 5px 10px; border: none; border-radius: 4px; background: #007bff; color: white; cursor: pointer; }
      .copyright { font-size: 12px; color: #888; }
      .progress-bar { height: 10px; background: #eee; border-radius: 5px; margin-top: 5px; overflow: hidden; position: relative; }
      .progress-track { height: 100%; background: #007bff; transition: width 0.3s ease; width: 0; }
      .progress-text { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); color: #333; font-size: 10px; mix-blend-mode: difference; color: white; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h1>文件上传</h1>
        <a href="/admin" class="admin-link">进入管理页面</a>
      </div>
      <div class="upload-area" id="uploadArea">
        <p>点击选择 或 拖拽文件到此处 (支持任意格式)</p>
        <input type="file" id="fileInput" multiple style="display: none">
        <input type="password" id="password-input" placeholder="设置访问密码 (可选)">
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
            <span>© 2025 by <a href="https://github.com/yutian81/CF-tgfile" target="_blank">yutian81</a></span>
          </div>
        </div>
      </div>
    </div>
    <script>
      async function setBingBackground() { try { const response = await fetch('/bing'); const data = await response.json(); if (data.status && data.data.length > 0) { const randomIndex = Math.floor(Math.random() * data.data.length); document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`; } } catch (error) { console.error('获取背景图失败:', error); } }
      setBingBackground(); setInterval(setBingBackground, 3600000);
      const uploadArea = document.getElementById('uploadArea');
      const fileInput = document.getElementById('fileInput');
      const previewArea = document.getElementById('previewArea');
      const urlArea = document.getElementById('urlArea');
      const passwordInput = document.getElementById('password-input');
      let uploadedUrls = [];
      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(e => { uploadArea.addEventListener(e, p, false); document.body.addEventListener(e, p, false); });
      function p(e) { e.preventDefault(); e.stopPropagation(); }
      ['dragenter', 'dragover'].forEach(e => uploadArea.addEventListener(e, () => uploadArea.classList.add('dragover'), false));
      ['dragleave', 'drop'].forEach(e => uploadArea.addEventListener(e, () => uploadArea.classList.remove('dragover'), false));
      uploadArea.addEventListener('click', (e) => { if(e.target.id !== 'password-input') fileInput.click() });
      fileInput.addEventListener('change', handleFiles);
      uploadArea.addEventListener('drop', (e) => handleFiles({ target: e.dataTransfer }), false);
      document.addEventListener('paste', async (e) => { const items = e.clipboardData.items; for (let item of items) { if (item.kind === 'file') { await uploadFile(item.getAsFile()); } } });
      
      async function handleFiles(e) {
        const config = await (await fetch('/config')).json();
        const files = Array.from(e.files);
        for (let file of files) {
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
        xhr.upload.addEventListener('progress', e => { if (e.lengthComputable) { const percent = Math.round((e.loaded / e.total) * 100); progressTrack.style.width = \`\${percent}%\`; progressText.textContent = \`\${percent}%\`; } });
        xhr.addEventListener('load', () => {
          try {
            const data = JSON.parse(xhr.responseText);
            if (xhr.status >= 200 && xhr.status < 300 && data.status === 1) {
              progressText.textContent = data.msg;
              uploadedUrls.push(data.url);
              urlArea.value = uploadedUrls.join('\\n');
              preview.classList.add('success');
            } else {
              progressText.textContent = data.error || '上传失败';
              preview.classList.add('error');
            }
          } catch (e) {
            progressText.textContent = '响应解析失败';
            preview.classList.add('error');
          }
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
        info.innerHTML = \`<div>\${file.name} (\${formatSize(file.size)})</div><div class="progress-bar"><div class="progress-track"></div><span class="progress-text">0%</span></div>\`;
        div.appendChild(info);
        return div;
      }
      function formatSize(bytes) { if (bytes === 0) return '0 B'; const u = ['B', 'KB', 'MB', 'GB']; const i = Math.floor(Math.log(bytes) / Math.log(1024)); return \`\${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} \${u[i]}\`; }
      function copyUrls(format) { let text = ''; switch (format) { case 'url': text = uploadedUrls.join('\\n'); break; case 'markdown': text = uploadedUrls.map(url => \`![](\${url})\`).join('\\n'); break; case 'html': text = uploadedUrls.map(url => \`<img src="\${url}" />\`).join('\\n'); break; } navigator.clipboard.writeText(text).then(() => alert('已复制到剪贴板')); }
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
      body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; background-size: cover; background-position: center; transition: background-image 1s ease-in-out; }
      .container { max-width: 1200px; margin: 0 auto; }
      .header { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(5px); padding: 15px 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }
      .header h2 { margin: 0; }
      .header-actions { display: flex; align-items: center; gap: 15px; }
      #fileCount { color: red; font-weight: bold; font-size: 1.2em; }
      .search { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 250px; }
      .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 20px; }
      .file-card { background: rgba(255, 255, 255, 0.8); border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); overflow: hidden; position: relative; display: flex; flex-direction: column; }
      .file-preview { height: 150px; display: flex; align-items: center; justify-content: center; background: #eee; }
      .file-preview img, .file-preview video { max-width: 100%; max-height: 100%; object-fit: contain; }
      .file-info { padding: 10px; font-size: 14px; word-break: break-all; flex-grow: 1; }
      .file-info div:first-child { font-weight: bold; }
      .file-actions { padding: 10px; border-top: 1px solid #eee; display: grid; grid-template-columns: repeat(3, 1fr); gap: 5px; }
      .file-checkbox { position: absolute; left: 10px; top: 10px; z-index: 10; transform: scale(1.2); }
      .btn { padding: 5px 10px; border: none; border-radius: 4px; cursor: pointer; color: white; text-decoration: none; text-align: center; }
      .btn-delete { background: #dc3545; } .btn-share { background: #007bff; } .btn-edit { background: #ffc107; } .btn-down { background: #28a745; grid-column: span 3; }
      .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.6); justify-content: center; align-items: center; z-index: 1000; }
      .modal-content { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.2); width: 90%; max-width: 400px; }
      #qrcode { margin: 15px auto; }
      .qr-link-container { display: flex; align-items: center; justify-content: center; margin-top: 10px; gap: 10px; }
      #qrLink { color: #007bff; text-decoration: none; word-break: break-all; }
      .form-group { margin-bottom: 15px; text-align: left; }
      .form-group label { display: block; margin-bottom: 5px; }
      .form-group input { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
      .modal-buttons { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h2>文件管理</h2>
        <div class="header-actions">
          <span id="fileCount">共 ${totalFiles} 个文件</span>
          <input type="text" class="search" placeholder="搜索文件名..." id="searchInput">
          <label><input type="checkbox" id="selectAllCheckbox"> 全选</label>
          <button class="btn btn-delete" id="deleteSelectedBtn">删除选中</button>
          <a href="/upload" style="text-decoration: none; color: #007bff;">返回上传</a>
        </div>
      </div>
      <div class="grid" id="fileGrid">${fileCards}</div>
      ${qrModal}
      ${editModal}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      async function setBingBackground() { try { const response = await fetch('/bing'); const data = await response.json(); if (data.status && data.data.length > 0) { const randomIndex = Math.floor(Math.random() * data.data.length); document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`; } } catch (error) { console.error('获取背景图失败:', error); } }
      setBingBackground(); setInterval(setBingBackground, 3600000);
      
      const searchInput = document.getElementById('searchInput');
      const fileGrid = document.getElementById('fileGrid');
      const selectAllCheckbox = document.getElementById('selectAllCheckbox');
      const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
      let currentShareUrl = '';

      searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        document.querySelectorAll('.file-card').forEach(card => {
          const fileName = card.dataset.name.toLowerCase();
          card.style.display = fileName.includes(searchTerm) ? 'flex' : 'none';
        });
      });

      selectAllCheckbox.addEventListener('change', (e) => {
        document.querySelectorAll('.file-checkbox').forEach(checkbox => checkbox.checked = e.target.checked);
      });

      deleteSelectedBtn.addEventListener('click', async () => {
        const selectedUrls = Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => cb.closest('.file-card').dataset.url);
        if (selectedUrls.length === 0) {
          alert('请先选择要删除的文件');
          return;
        }
        if (confirm(\`确定要删除选中的 \${selectedUrls.length} 个文件吗？\`)) {
          deleteFiles(selectedUrls);
        }
      });

      async function deleteFiles(urls) {
        try {
          const response = await fetch('/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls })
          });
          const result = await response.json();
          if (!response.ok) throw new Error(result.error || '删除失败');
          
          let successCount = 0;
          result.results.forEach(res => {
              if (res.success) {
                  const card = document.querySelector(\`[data-url="\${res.url}"]\`);
                  if (card) card.remove();
                  successCount++;
              } else {
                  console.error(\`删除 \${res.url} 失败: \${res.message}\`);
              }
          });
          alert(\`成功删除 \${successCount} 个文件。\`);
          document.getElementById('fileCount').textContent = \`共 \${document.querySelectorAll('.file-card').length} 个文件\`;
        } catch (error) {
          alert('删除操作失败: ' + error.message);
        }
      }
      
      function showQRCode(url) {
        currentShareUrl = url;
        const modal = document.getElementById('qrModal');
        const qrcodeDiv = document.getElementById('qrcode');
        const qrLink = document.getElementById('qrLink');
        qrcodeDiv.innerHTML = '';
        new QRCode(qrcodeDiv, { text: url, width: 200, height: 200 });
        qrLink.href = url;
        qrLink.textContent = url;
        modal.style.display = 'flex';
      }

      function handleCopyUrl() {
        navigator.clipboard.writeText(currentShareUrl).then(() => alert('链接已复制'));
      }

      function openEditModal(url, name, password) {
        document.getElementById('editFileUrl').value = url;
        document.getElementById('editFileName').value = name;
        document.getElementById('editFilePassword').value = password;
        document.getElementById('editModal').style.display = 'flex';
      }

      function closeModal(modalId) {
        document.getElementById(modalId).style.display = 'none';
      }

      document.getElementById('editForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('editFileUrl').value;
        const newName = document.getElementById('editFileName').value;
        const newPassword = document.getElementById('editFilePassword').value;

        try {
            const response = await fetch('/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, newName, newPassword })
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || '更新失败');

            alert('更新成功');
            const card = document.querySelector(\`[data-url="\${url}"]\`);
            if (card) {
                card.dataset.name = newName;
                card.dataset.password = newPassword;
                card.querySelector('.file-info div:first-child').textContent = newName;
                card.querySelector('.btn-edit').setAttribute('onclick', \`openEditModal('\${url}', '\${newName}', '\${newPassword}')\`);
            }
            closeModal('editModal');
        } catch (error) {
            alert('更新失败: ' + error.message);
        }
      });

      window.onclick = function(event) {
        if (event.target.classList.contains('modal')) {
          event.target.style.display = 'none';
        }
      }
    </script>
  </body>
  </html>`;
}
