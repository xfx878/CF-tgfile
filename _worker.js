// Due to Telegram's limitations, although files over 20M can be uploaded, a direct link address cannot be returned.
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
      cookie: Number(env.COOKIE) || 7, // Cookie validity defaults to 7 days
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
    
    // Define routes
    const routes = {
      '/': () => handleAuthRequest(request, config),
      '/login': () => handleLoginRequest(request, config),
      '/upload': () => handleUploadRequest(request, config),
      '/admin': () => handleAdminRequest(request, config),
      '/delete': () => handleDeleteRequest(request, config),
      '/update': () => handleUpdateRequest(request, config), // New route for updating file info
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
      // Decode token and verify expiration
      const tokenData = JSON.parse(atob(authToken[1]));
      const now = Date.now();           
      // Check if token is expired
      if (now > tokenData.expiration) {
        console.log("Token has expired");
        return false;
      }          
      // If token is valid, return whether the username matches
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
    // Use authenticate function to check if the user is authenticated
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
      // Create token data including username and expiration time
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
    if (!messageId) throw new Error('Failed to get Telegram message ID');

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
    } else if (error.message.includes('Failed to get file ID') || error.message.includes('Failed to get Telegram message ID')) {
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

  const { results: fileList = [] } = await config.database.prepare(
    `SELECT url, fileId, message_id, created_at, file_name, file_size, mime_type, password
    FROM files
    ORDER BY created_at DESC`
  ).all();

  const fileCount = fileList.length;

  const fileCards = fileList.map(file => {
    const fileName = file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const filePassword = file.password || '';
    return `
      <div class="file-card" data-url="${file.url}" data-filename="${fileName}" data-password="${filePassword}">
        <input type="checkbox" class="file-checkbox">
        <div class="file-preview">
          ${getPreviewHtml(file.url, file.mime_type)}
        </div>
        <div class="file-info">
          <div class="file-name" title="${fileName}">${fileName}</div>
          <div>${fileSize}</div>
          <div>${createdAt}</div>
        </div>
        <div class="file-actions">
          <button class="btn btn-share" onclick="showQRCode('${file.url}')">分享</button>
          <button class="btn btn-edit" onclick="editFile('${file.url}', '${fileName}', '${filePassword}')">编辑</button>
          <a class="btn btn-down" href="${file.url}" download="${fileName}">下载</a>
        </div>
      </div>
    `;
  }).join('');
  
  const html = generateAdminPage(fileCards, fileCount);
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

// Get preview for file types
function getPreviewHtml(url, mimeType) {
    const isImage = mimeType && mimeType.startsWith('image/');
    const isVideo = mimeType && mimeType.startsWith('video/');
    const isAudio = mimeType && mimeType.startsWith('audio/');

    if (isImage) {
        return `<img src="${url}" alt="Preview" loading="lazy">`;
    } else if (isVideo) {
        return `<video src="${url}" controls preload="metadata"></video>`;
    } else if (isAudio) {
        return `<audio src="${url}" controls preload="metadata"></audio>`;
    } else {
        return `<div style="font-size: 48px">📄</div>`;
    }
}


// Fetch file and cache
async function handleFileRequest(request, config) {
    const url = new URL(request.url);
    const cache = caches.default;
    const cacheKey = new Request(url.origin + url.pathname);

    try {
        const file = await config.database.prepare(
            `SELECT fileId, file_name, mime_type, password
            FROM files WHERE url = ?`
        ).bind(url.origin + url.pathname).first();

        if (!file) {
            return new Response('File not found', {
                status: 404,
                headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
            });
        }

        // Check for password protection
        if (file.password) {
            const providedPassword = url.searchParams.get('pwd');
            if (providedPassword !== file.password) {
                return new Response(generatePasswordPromptPage(request.url), {
                    status: 401,
                    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
                });
            }
        }

        const cachedResponse = await cache.match(cacheKey);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        const tgResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/getFile?file_id=${file.fileId}`);
        if (!tgResponse.ok) {
            throw new Error('Failed to get file info from Telegram');
        }
        const tgData = await tgResponse.json();
        const filePath = tgData.result?.file_path;
        if (!filePath) {
            throw new Error('Invalid file path from Telegram');
        }

        const fileUrl = `https://api.telegram.org/file/bot${config.tgBotToken}/${filePath}`;
        const fileResponse = await fetch(fileUrl);
        if (!fileResponse.ok) {
            throw new Error('Failed to download file from Telegram');
        }

        const response = new Response(fileResponse.body, {
            headers: {
                'Content-Type': file.mime_type || 'application/octet-stream',
                'Cache-Control': 'public, max-age=31536000',
                'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(file.file_name || '')}`
            }
        });

        await cache.put(cacheKey, response.clone());
        return response;

    } catch (error) {
        console.error(`[File Request Error] ${error.message} for ${url}`);
        return new Response('Internal server error', {
            status: 500,
            headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
        });
    }
}


// Handle file deletion
async function handleDeleteRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  try {
    const { urls } = await request.json();
    if (!urls || !Array.isArray(urls)) {
      return new Response(JSON.stringify({ error: 'Invalid URLs' }), {
        status: 400, 
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const results = [];
    for (const url of urls) {
        const file = await config.database.prepare(
            'SELECT fileId, message_id FROM files WHERE url = ?'
        ).bind(url).first();
        
        if (file) {
            try {
                const deleteResponse = await fetch(
                    `https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`
                );
                if (!deleteResponse.ok) {
                   // Even if TG deletion fails, we proceed to delete from DB
                }
            } catch (e) {
                // Network error, proceed to delete from DB
            }
            await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
            results.push({ url, success: true });
        } else {
            results.push({ url, success: false, error: 'File not found' });
        }
    }
    
    return new Response(JSON.stringify({ success: true, results }), {
        headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Handle file info update
async function handleUpdateRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }

    try {
        const { url, fileName, password } = await request.json();
        if (!url || !fileName) {
            return new Response(JSON.stringify({ error: 'Invalid input' }), { status: 400 });
        }

        await config.database.prepare(
            'UPDATE files SET file_name = ?, password = ? WHERE url = ?'
        ).bind(fileName, password || null, url).run();

        return new Response(JSON.stringify({ success: true, message: 'File updated successfully' }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error(`[Update Error] ${error.message}`);
        return new Response(JSON.stringify({ error: 'Failed to update file' }), { status: 500 });
    }
}

// Supported file types for upload
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
  return types[ext.toLowerCase()] || 'application/octet-stream';
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
function generatePasswordPromptPage(url) {
    return `<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>需要密码</title>
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; font-family: sans-serif; }
            .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; }
            h2 { margin-bottom: 20px; }
            input { width: 100%; padding: 10px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>请输入密码访问文件</h2>
            <form method="GET" action="${url.split('?')[0]}">
                <input type="password" name="pwd" placeholder="密码" required>
                <button type="submit">确认</button>
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
    <meta name="description" content="Telegram File Storage and Sharing Platform">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录</title>
    <style>
      body { display: flex; justify-content: center; align-items: center; height: 100vh; background: #f5f5f5; font-family: Arial, sans-serif; background-size: cover; background-position: center; transition: background-image 1s ease-in-out; }
      .login-container { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
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
          if (data.status && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) { console.error('Failed to get background image:', error); }
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
    <meta name="description" content="Telegram File Storage and Sharing Platform">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件上传</title>
    <style>
      body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f5f5f5; margin: 0; background-size: cover; background-position: center; transition: background-image 1s ease-in-out; }
      .container { max-width: 800px; width: 100%; background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 10px 40px 20px 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow-y: auto; max-height: 90vh; }
      .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
      .upload-area { border: 2px dashed #666; padding: 40px; text-align: center; margin-bottom: 10px; border-radius: 8px; transition: all 0.3s; cursor: pointer; }
      .upload-area.dragover { border-color: #007bff; background: #f0f8ff; }
      #password-input { width: calc(100% - 22px); padding: 10px; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 10px; }
      .preview-area { margin-top: 20px; }
      .preview-item { display: flex; align-items: center; padding: 10px; border: 1px solid #ddd; margin-bottom: 10px; border-radius: 4px; }
      .preview-item img { max-width: 100px; max-height: 100px; margin-right: 10px; }
      .preview-item .info { flex-grow: 1; }
      .url-area textarea { width: 100%; min-height: 100px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; background: rgba(255, 255, 255, 0.5); color: #333; box-sizing: border-box; }
      .admin-link { color: #007bff; text-decoration: none; }
      .admin-link:hover { text-decoration: underline; }
      .button-group { margin-top: 10px; display: flex; justify-content: space-between; align-items: center; }
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
        <p>点击选择 或 拖拽任意格式文件到此处</p>
        <input type="file" id="fileInput" multiple style="display: none">
      </div>
      <input type="password" id="password-input" placeholder="可选：为所有上传文件设置访问密码">
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
      async function setBingBackground() { /* ... same as login ... */ }
      setBingBackground(); setInterval(setBingBackground, 3600000);

      const uploadArea = document.getElementById('uploadArea');
      const fileInput = document.getElementById('fileInput');
      const previewArea = document.getElementById('previewArea');
      const urlArea = document.getElementById('urlArea');
      const passwordInput = document.getElementById('password-input');
      let uploadedUrls = [];

      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(e => {
        uploadArea.addEventListener(e, p => { p.preventDefault(); p.stopPropagation(); }, false);
        document.body.addEventListener(e, p => { p.preventDefault(); p.stopPropagation(); }, false);
      });
      ['dragenter', 'dragover'].forEach(e => uploadArea.addEventListener(e, () => uploadArea.classList.add('dragover'), false));
      ['dragleave', 'drop'].forEach(e => uploadArea.addEventListener(e, () => uploadArea.classList.remove('dragover'), false));

      uploadArea.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', (e) => handleFiles(e.target.files));
      uploadArea.addEventListener('drop', (e) => handleFiles(e.dataTransfer.files), false);
      document.addEventListener('paste', (e) => handleFiles((e.clipboardData || window.clipboardData).files));

      async function handleFiles(files) {
        const config = await (await fetch('/config')).json();
        for (const file of files) {
          if (file.size > config.maxSizeMB * 1024 * 1024) {
            alert(\`文件 \${file.name} 超过 \${config.maxSizeMB}MB 限制\`);
            continue;
          }
          uploadFile(file);
        }
      }

      function uploadFile(file) {
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
        
        const formData = new FormData();
        formData.append('file', file);
        if (passwordInput.value) {
            formData.append('password', passwordInput.value);
        }
        xhr.open('POST', '/upload', true);
        xhr.send(formData);
      }

      function createPreview(file) {
        const div = document.createElement('div');
        div.className = 'preview-item';
        if (file.type.startsWith('image/')) {
          const img = document.createElement('img');
          img.src = URL.createObjectURL(file);
          img.onload = () => URL.revokeObjectURL(img.src);
          div.appendChild(img);
        }
        div.innerHTML += \`
          <div class="info">
            <div>\${file.name}</div>
            <div>\${formatSize(file.size)}</div>
            <div class="progress-bar">
              <div class="progress-track"></div>
              <span class="progress-text">0%</span>
            </div>
          </div>\`;
        return div;
      }
      
      function formatSize(bytes) { /* ... same as before ... */ }
      function updateUrlArea() { urlArea.value = uploadedUrls.join('\\n'); }
      function copyUrls(format) {
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
function generateAdminPage(fileCards, fileCount) {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <link rel="shortcut icon" href="https://pan.811520.xyz/2025-02/1739241502-tgfile-favicon.ico" type="image/x-icon">
    <meta name="description" content="Telegram File Storage and Sharing Platform">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件管理</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; background-size: cover; background-position: center; transition: background-image 1s ease-in-out; }
      .container { max-width: 1200px; margin: 0 auto; }
      .header { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 15px 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }
      h2 { margin: 0; }
      .header-left, .header-right { display: flex; align-items: center; gap: 20px; }
      #file-stats { color: red; font-size: 1.2em; font-weight: bold; }
      .search { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 250px; }
      .btn { padding: 8px 12px; border: none; border-radius: 4px; cursor: pointer; color: white; }
      .btn-action { background: #007bff; } .btn-action:hover { background: #0056b3; }
      .btn-danger { background: #dc3545; } .btn-danger:hover { background: #c82333; }
      .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 20px; }
      .file-card { background: rgba(255, 255, 255, 0.8); border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; position: relative; }
      .file-preview { height: 150px; display: flex; align-items: center; justify-content: center; }
      .file-preview img, .file-preview video { max-width: 100%; max-height: 100%; object-fit: contain; }
      .file-info { padding: 10px; font-size: 14px; }
      .file-name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .file-actions { padding: 10px; border-top: 1px solid #eee; display: flex; justify-content: space-around; }
      .file-actions .btn, .file-actions .btn-down { font-size: 12px; padding: 5px 8px; }
      .btn-share { background: #17a2b8; } .btn-edit { background: #ffc107; } .btn-down { background: #28a745; text-decoration: none; color: white; display: inline-block; }
      .file-checkbox { position: absolute; left: 10px; top: 10px; z-index: 10; transform: scale(1.5); }
      .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.5); justify-content: center; align-items: center; }
      .modal-content { background-color: #fefefe; margin: auto; padding: 20px; border: 1px solid #888; width: 80%; max-width: 500px; border-radius: 10px; text-align: center; }
      #qrcode { margin: 20px auto; } #share-link-container { margin-top: 15px; display: flex; align-items: center; } #share-link { flex-grow: 1; padding: 5px; border: 1px solid #ccc; border-radius: 4px; }
      .modal-buttons { display: flex; gap: 10px; justify-content: center; margin-top: 15px; }
      #editModal .form-group { margin-bottom: 15px; text-align: left; } #editModal label { display: block; margin-bottom: 5px; } #editModal input { width: 100%; padding: 8px; box-sizing: border-box; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="header-left">
          <h2>文件管理</h2>
          <span id="file-stats">总计 ${fileCount} 个文件</span>
        </div>
        <div class="header-right">
          <input type="checkbox" id="selectAllCheckbox" title="全选">
          <button id="deleteSelectedBtn" class="btn btn-danger">删除选中</button>
          <input type="text" class="search" placeholder="搜索文件..." id="searchInput">
          <a href="/upload" class="btn btn-action">返回上传</a>
        </div>
      </div>
      <div class="grid" id="fileGrid">${fileCards}</div>
    </div>

    <!-- Share Modal -->
    <div id="qrModal" class="modal">
      <div class="modal-content">
        <div id="qrcode"></div>
        <div id="share-link-container">
            <a id="share-link-anchor" href="#" target="_blank" style="margin-right: 10px;">点击跳转</a>
            <input type="text" id="share-link" readonly>
            <button class="btn btn-action" onclick="copyShareLink()">复制</button>
        </div>
        <div class="modal-buttons">
          <button class="btn btn-danger" onclick="closeModal('qrModal')">关闭</button>
        </div>
      </div>
    </div>

    <!-- Edit Modal -->
    <div id="editModal" class="modal">
      <div class="modal-content">
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
        <div class="modal-buttons">
          <button class="btn btn-action" onclick="saveFileChanges()">保存</button>
          <button class="btn btn-danger" onclick="closeModal('editModal')">取消</button>
        </div>
      </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      async function setBingBackground() { /* ... same as login ... */ }
      setBingBackground(); setInterval(setBingBackground, 3600000);

      const searchInput = document.getElementById('searchInput');
      const fileGrid = document.getElementById('fileGrid');
      const selectAllCheckbox = document.getElementById('selectAllCheckbox');
      const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');

      searchInput.addEventListener('input', e => {
        const term = e.target.value.toLowerCase();
        document.querySelectorAll('.file-card').forEach(card => {
          const name = card.dataset.filename.toLowerCase();
          card.style.display = name.includes(term) ? '' : 'none';
        });
      });

      selectAllCheckbox.addEventListener('change', e => {
        document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = e.target.checked);
      });

      deleteSelectedBtn.addEventListener('click', async () => {
        const selected = Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => cb.closest('.file-card').dataset.url);
        if (selected.length === 0) return alert('请先选择要删除的文件');
        if (!confirm(\`确定要删除选中的 \${selected.length} 个文件吗？\`)) return;

        try {
            const response = await fetch('/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls: selected })
            });
            const data = await response.json();
            if (data.success) {
                selected.forEach(url => document.querySelector(\`[data-url="\${url}"]\`)?.remove());
                alert('选中的文件已删除');
                location.reload();
            } else { throw new Error(data.error); }
        } catch (error) { alert('删除失败: ' + error.message); }
      });

      let qrCodeInstance = null;
      function showQRCode(url) {
        const modal = document.getElementById('qrModal');
        const qrcodeDiv = document.getElementById('qrcode');
        qrcodeDiv.innerHTML = '';
        qrCodeInstance = new QRCode(qrcodeDiv, { text: url, width: 200, height: 200 });
        document.getElementById('share-link').value = url;
        document.getElementById('share-link-anchor').href = url;
        modal.style.display = 'flex';
      }

      function copyShareLink() {
        const linkInput = document.getElementById('share-link');
        linkInput.select();
        document.execCommand('copy');
        alert('链接已复制');
      }
      
      function editFile(url, name, password) {
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
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, fileName, password })
            });
            const data = await response.json();
            if (data.success) {
                alert('更新成功');
                location.reload();
            } else { throw new Error(data.error); }
        } catch (error) { alert('更新失败: ' + error.message); }
      }

      function closeModal(modalId) { document.getElementById(modalId).style.display = 'none'; }
      window.onclick = e => {
        if (e.target.classList.contains('modal')) {
            e.target.style.display = 'none';
        }
      }
    </script>
  </body>
  </html>`;
}
