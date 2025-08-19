// Due to Telegram's limitations, although files over 20M can be uploaded, a direct link cannot be returned.
// Therefore, the code is modified to prevent uploads of files larger than 20MB.

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
      '/delete-multiple': () => handleMultipleDeleteRequest(request, config), // New route for bulk deletion
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

// Authentication handler
function authenticate(request, config) {
  const cookies = request.headers.get("Cookie") || "";
  const authToken = cookies.match(/auth_token=([^;]+)/); // Get auth_token from cookie
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

// Route handler
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

// Login handler
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

// File upload handler
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
    
    const ext = (file.name.split('.').pop() || '').toLowerCase();  //get file extension
    const mimeType = getContentType(ext);  // get file type
    const [mainType] = mimeType.split('/'); // get main type
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
    // Set different status codes based on the error message
    let statusCode = 500; // Default 500
    if (error.message.includes(`文件超过${config.maxSizeMB}MB限制`)) {
      statusCode = 400; // Client error: file size exceeded
    } else if (error.message.includes('Telegram参数配置错误')) {
      statusCode = 502; // Gateway error: failed to communicate with Telegram
    } else if (error.message.includes('未获取到文件ID') || error.message.includes('未获取到tg消息ID')) {
      statusCode = 500; // Server internal error: abnormal data returned from Telegram
    } else if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
      statusCode = 504; // Network timeout or disconnection
    }
    return new Response(
      JSON.stringify({ status: 0, msg: "✘ 上传失败", error: error.message }),
      { status: statusCode, headers: { 'Content-Type': 'application/json' }}
    );
  }
}

// File management and preview handler
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
  const totalFiles = fileList.length;
  const totalSize = fileList.reduce((sum, file) => sum + (file.file_size || 0), 0);

  const fileCards = fileList.map(file => {
    const fileName = file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const passwordInfo = file.password 
        ? `<div class="password-info" onclick="copyToClipboard('${file.password}', this)">密码: ${file.password} </div>` 
        : '<div>无密码</div>';
    
    // File preview information and action elements
    return `
      <div class="file-card" data-url="${file.url}">
        <input type="checkbox" class="file-checkbox">
        <div class="file-preview">
          ${getPreviewHtml(file.url)}
        </div>
        <div class="file-info">
          <div>${fileName}</div>
          <div>${fileSize}</div>
          <div>${createdAt}</div>
          ${passwordInfo}
        </div>
        <div class="file-actions">
          <button class="btn btn-copy" onclick="showQRCode('${file.url}')">分享</button>
          <a class="btn btn-down" href="${file.url}" download="${fileName}">下载</a>
          <button class="btn btn-delete" onclick="deleteFile('${file.url}')">删除</button>
        </div>
      </div>
    `;
  }).join('');

  // QR code sharing element
  const qrModal = `
    <div id="qrModal" class="qr-modal">
      <div class="qr-content">
        <div id="qrcode"></div>
        <div class="qr-buttons">
          <button class="qr-copy" onclick="handleCopyUrl()">复制链接</button>
          <button class="qr-close" onclick="closeQRModal()">关闭</button>
        </div>
      </div>
    </div>
  `;

  const html = generateAdminPage(fileCards, qrModal, totalFiles, totalSize);
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

// File search handler
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

// File types that support preview
function getPreviewHtml(url) {
  const ext = (url.split('.').pop() || '').toLowerCase();
  const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'].includes(ext);
  const isVideo = ['mp4', 'webm'].includes(ext);
  const isAudio = ['mp3', 'wav', 'ogg'].includes(ext);

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

// Get and cache files
async function handleFileRequest(request, config) {
  const url = new URL(request.url);
  const cache = caches.default;
  const cacheKey = new Request(url.toString());

  try {
    // Attempt to get from cache
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      console.log(`[Cache Hit] ${url.toString()}`);
      return cachedResponse;
    }

    // Query file from database
    const file = await config.database.prepare(
      `SELECT fileId, message_id, file_name, mime_type, password
      FROM files WHERE url = ?`
    ).bind(url.origin + url.pathname).first();

    if (!file) {
      console.log(`[404] File not found: ${url.toString()}`);
      return new Response('文件不存在', { 
        status: 404,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }
    
    // Handle password protection
    if (file.password) {
        let providedPassword = '';
        if (request.method === 'POST') {
            const formData = await request.formData();
            providedPassword = formData.get('password');
        } else {
            providedPassword = url.searchParams.get('pwd');
        }

        if (providedPassword !== file.password) {
            return new Response(generatePasswordPromptPage(url.pathname, providedPassword ? '密码错误' : ''), {
                status: 401,
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
    const contentType = file.mime_type || getContentType(url.pathname.split('.').pop().toLowerCase());

    // Create response and cache
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
    console.log(`[Cache Set] ${url.toString()}`);
    return response;

  } catch (error) {
    console.error(`[Error] ${error.message} for ${url.toString()}`);
    return new Response('服务器内部错误', { 
      status: 500,
      headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
    });
  }
}

// File deletion handler
async function handleDeleteRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ error: '认证失败' }), { status: 401, headers: { 'Content-Type': 'application/json' }});
  }

  try {
    const { url } = await request.json();
    if (!url || typeof url !== 'string') {
      return new Response(JSON.stringify({ error: '无效的URL' }), {
        status: 400, 
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const file = await config.database.prepare(
      'SELECT fileId, message_id FROM files WHERE url = ?'
    ).bind(url).first();    
    if (!file) {
      return new Response(JSON.stringify({ error: '文件不存在' }), { 
        status: 404, 
        headers: { 'Content-Type': 'application/json' }
      });
    }    

    let deleteError = null;

    try {
      const deleteResponse = await fetch(
        `https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`
      );
      if (!deleteResponse.ok) {
        const errorData = await deleteResponse.json();
        console.error(`[Telegram API Error] ${JSON.stringify(errorData)}`);
        throw new Error(`Telegram 消息删除失败: ${errorData.description}`);
      }
    } catch (error) { deleteError = error.message; }

    // Delete database table data, even if Telegram deletion fails, the database record will be deleted
    await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
    
    return new Response(
      JSON.stringify({ 
        success: true,
        message: deleteError ? `文件已从数据库删除，但Telegram消息删除失败: ${deleteError}` : '文件删除成功'
      }),
      { headers: { 'Content-Type': 'application/json' }}
    );

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(
      JSON.stringify({ 
        error: error.message.includes('message to delete not found') ? 
              '文件已从频道移除' : error.message 
      }),
      { status: 500, headers: { 'Content-Type': 'application/json' }}
    );
  }
}

// Bulk delete handler
async function handleMultipleDeleteRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: '认证失败' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }

    try {
        const { urls } = await request.json();
        if (!Array.isArray(urls) || urls.length === 0) {
            return new Response(JSON.stringify({ error: '无效的URL列表' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        const results = [];
        for (const url of urls) {
            const file = await config.database.prepare('SELECT message_id FROM files WHERE url = ?').bind(url).first();
            if (file) {
                try {
                    const deleteResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`);
                    if (!deleteResponse.ok) {
                        const errorData = await deleteResponse.json();
                        results.push({ url, success: false, error: `Telegram: ${errorData.description}` });
                    } else {
                        results.push({ url, success: true });
                    }
                } catch (e) {
                    results.push({ url, success: false, error: e.message });
                }
                await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
            } else {
                results.push({ url, success: false, error: '文件未在数据库中找到' });
            }
        }
        
        // Clear cache for deleted files
        const cache = caches.default;
        for (const url of urls) {
            await cache.delete(new Request(url));
        }

        return new Response(JSON.stringify({ success: true, results }), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        console.error(`[Multiple Delete Error] ${error.message}`);
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}


// Supported upload file types
function getContentType(ext) {
  const types = {
    'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png', 'gif': 'image/gif',
    'webp': 'image/webp', 'svg': 'image/svg+xml', 'ico': 'image/x-icon',
    'mp4': 'video/mp4', 'webm': 'video/webm',
    'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'ogg': 'audio/ogg',
    'pdf': 'application/pdf', 'txt': 'text/plain', 'md': 'text/markdown',
    'zip': 'application/zip', 'rar': 'application/x-rar-compressed',
    'json': 'application/json', 'xml': 'application/xml', 'js': 'application/javascript',
    'css': 'text/css', 'html': 'text/html',
    'doc': 'application/msword', 'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel', 'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt': 'application/vnd.ms-powerpoint', 'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'apk': 'application/vnd.android.package-archive',
    'ipa': 'application/octet-stream',
    'exe': 'application/x-msdownload',
    'dmg': 'application/x-apple-diskimage',
    'default': 'application/octet-stream'
  };
  return types[ext] || types['default'];
}

async function handleBingImagesRequest() {
  const cache = caches.default;
  const cacheKey = new Request('https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=5');
  
  const cachedResponse = await cache.match(cacheKey);
  if (cachedResponse) {
    console.log('Returning cached response');
    return cachedResponse;
  }
  
  try {
    const res = await fetch(cacheKey);
    if (!res.ok) {
      console.error(`Bing API 请求失败，状态码：${res.status}`);
      return new Response('请求 Bing API 失败', { status: res.status });
    }
    
    const bingData = await res.json();
    const images = bingData.images.map(image => ({ url: `https://cn.bing.com${image.url}` }));
    const returnData = { status: true, message: "操作成功", data: images };
    
    const response = new Response(JSON.stringify(returnData), { 
      status: 200, 
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=21600',
        'Access-Control-Allow-Origin': '*' 
      }
    });
    
    await cache.put(cacheKey, response.clone());
    console.log('响应数据已缓存');
    return response;
  } catch (error) {
    console.error('请求 Bing API 过程中发生错误:', error);
    return new Response('请求 Bing API 失败', { status: 500 });
  }
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
      body {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        background-size: cover;
        background-position: center;
        background-color: #f5f5f5;
        font-family: Arial, sans-serif;
        transition: background-image 1s ease-in-out;
      }
      .login-container {
        background: rgba(255, 255, 255, 0.8);
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        width: 100%;
        max-width: 400px;
      }
      .form-group {
        margin-bottom: 1rem;
      }
      input {
        width: 100%;
        padding: 0.75rem;
        border: 1px solid #ddd;
        border-radius: 4px;
        font-size: 1rem;
        box-sizing: border-box;
        background: rgba(255, 255, 255, 0.7);
        color: #333;
      }
      button {
        width: 100%;
        padding: 0.75rem;
        background: #007bff;
        color: white;
        border: none;
        border-radius: 4px;
        font-size: 1rem;
        cursor: pointer;
        margin-bottom: 10px;
      }
      button:hover {
        background: #0056b3;
      }
      .error {
        color: #dc3545;
        margin-top: 1rem;
        display: none;
      }
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
      // Add background image related functions
      async function setBingBackground() {
        try {
          const response = await fetch('/bing', { cache: 'no-store' });  // Disable cache
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) {
          console.error('获取背景图失败:', error);
        }
      }
      // Set background image on page load
      setBingBackground(); 
      // Update background image every hour
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
        font-family: Arial, sans-serif;
        transition: background-image 1s ease-in-out;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        background-size: cover;
        background-position: center;
        background-color: #f5f5f5;
        margin: 0;
      }
      .container {
        max-width: 800px;
        width: 100%;
        background: rgba(255, 255, 255, 0.8);
        backdrop-filter: blur(5px);
        padding: 10px 40px 20px 40px;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        overflow-y: auto;
        max-height: 90vh;
      }
      .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 10px;
      }
      .upload-area {
        border: 2px dashed #666;
        padding: 40px;
        text-align: center;
        margin: 0 auto;
        border-radius: 8px;
        transition: all 0.3s;
        box-sizing: border-box;
      }
      .upload-area.dragover {
        border-color: #007bff;
        background: #f8f9fa;
      }
      .password-input {
        margin-top: 15px;
        text-align: center;
      }
      .password-input input {
        padding: 8px;
        border-radius: 4px;
        border: 1px solid #ddd;
        width: 250px;
      }
      .preview-area {
        margin-top: 20px;
      }
      .preview-item {
        display: flex;
        align-items: center;
        padding: 10px;
        border: 1px solid #ddd;
        margin-bottom: 10px;
        border-radius: 4px;
      }
      .preview-item img {
        max-width: 100px;
        max-height: 100px;
        margin-right: 10px;
      }
      .preview-item .info {
        flex-grow: 1;
      }
      .url-area {
        margin-top: 10px;
        width: calc(100% - 20px);
        box-sizing: border-box;
      }
      .url-area textarea {
        width: 100%;
        min-height: 100px;
        padding: 10px;
        border: 1px solid #ddd;
        border-radius: 4px;
        background: rgba(255, 255, 255, 0.5);
        color: #333;       
      }
      .admin-link {
        display: inline-block;
        margin-left: auto;
        color: #007bff;
        text-decoration: none;
      }
      .admin-link:hover {
        text-decoration: underline;
      }
      .button-group {
        margin-top: 10px;
        margin-bottom: 10px;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
      .button-container button {
        margin-right: 10px;
        padding: 5px 10px;
        border: none;
        border-radius: 4px;
        background: #007bff;
        color: white;
        cursor: pointer;
      }
      .button-container button:hover {
        background: #0056b3;
      }
      .copyright {
      margin-left: auto;
      font-size: 12px;
      color: #888;
      }
      .progress-bar {
        height: 20px;
        background: #eee;
        border-radius: 10px;
        margin: 8px 0;
        overflow: hidden;
        position: relative;
      }
      .progress-track {
        height: 100%;
        background: #007bff;
        transition: width 0.3s ease;
        width: 0;
      }
      .progress-text {
        position: absolute;
        left: 50%;
        top: 50%;
        transform: translate(-50%, -50%);
        color: white;
        font-size: 12px;
        text-shadow: 1px 1px 1px #000;
      }
      .success .progress-track {
        background: #28a745;
      }
      .error .progress-track {
        background: #dc3545;
      }
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
      </div>
      <div class="password-input">
        <input type="text" id="passwordInput" placeholder="设置访问密码 (可选)">
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
            <span>© 2025 Copyright by
            <a href="https://github.com/yutian81/CF-tgfile" target="_blank" style="text-decoration: none; color: inherit;">yutian81's GitHub</a> | 
            <a href="https://blog.811520.xyz/" target="_blank" style="text-decoration: none; color: inherit;">青云志</a>
            </span>
          </div>
        </div>
      </div>
    </div>

    <script>
      // Add background image related functions
      async function setBingBackground() {
        try {
          const response = await fetch('/bing', { cache: 'no-store' });  // Disable cache
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) {
          console.error('获取背景图失败:', error);
        }
      }
      // Set background image on page load
      setBingBackground(); 
      // Update background image every hour
      setInterval(setBingBackground, 3600000);

      const uploadArea = document.getElementById('uploadArea');
      const fileInput = document.getElementById('fileInput');
      const passwordInput = document.getElementById('passwordInput');
      const previewArea = document.getElementById('previewArea');
      const urlArea = document.getElementById('urlArea');
      let uploadedUrls = [];

      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
      });

      function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
      }

      ['dragenter', 'dragover'].forEach(eventName => {
        uploadArea.addEventListener(eventName, highlight, false);
      });

      ['dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, unhighlight, false);
      });

      function highlight(e) {
        uploadArea.classList.add('dragover');
      }

      function unhighlight(e) {
        uploadArea.classList.remove('dragover');
      }

      uploadArea.addEventListener('drop', handleDrop, false);
      uploadArea.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', handleFiles);

      function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFiles({ target: { files } });
      }

      document.addEventListener('paste', async (e) => {
        const items = (e.clipboardData || e.originalEvent.clipboardData).items;
        for (let item of items) {
          if (item.kind === 'file') {
            const file = item.getAsFile();
            await uploadFile(file);
          }
        }
      });

      async function handleFiles(e) {
        const response = await fetch('/config');
        if (!response.ok) {
          throw new Error('Failed to fetch config');
        }      
        const config = await response.json();
        const files = Array.from(e.target.files);
        for (let file of files) {
          // Check size directly before uploading
          if (file.size > config.maxSizeMB * 1024 * 1024) {
            alert(\`文件 \${file.name} 超过\${config.maxSizeMB}MB限制\`);
            continue; // Skip this file and continue with the next
          }
          await uploadFile(file); // Continue uploading
        }
      }

      async function uploadFile(file) {
        const preview = createPreview(file);
        previewArea.appendChild(preview);

        const xhr = new XMLHttpRequest();
        const progressTrack = preview.querySelector('.progress-track');
        const progressText = preview.querySelector('.progress-text');

        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            progressTrack.style.width = \`\${percent}%\`;
            progressText.textContent = \`\${percent}%\`;
          }
        });

        xhr.addEventListener('load', () => {
          try {
            const data = JSON.parse(xhr.responseText);
            const progressText = preview.querySelector('.progress-text');          
            if (xhr.status >= 200 && xhr.status < 300 && data.status === 1) {
              progressText.textContent = data.msg;
              uploadedUrls.push(data.url);
              updateUrlArea();
              preview.classList.add('success');
            } else {
              const errorMsg = [data.msg, data.error || '未知错误'].filter(Boolean).join(' | ');
              progressText.textContent = errorMsg;
              preview.classList.add('error');
            }
          } catch (e) {
            preview.querySelector('.progress-text').textContent = '✗ 响应解析失败';
            preview.classList.add('error');
          }
        });

        const formData = new FormData();
        formData.append('file', file);
        const password = passwordInput.value.trim();
        if (password) {
            formData.append('password', password);
        }
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
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
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
          case 'url':
            text = uploadedUrls.join('\\n');
            break;
          case 'markdown':
            text = uploadedUrls.map(url => \`![](\${url})\`).join('\\n');
            break;
          case 'html':
            text = uploadedUrls.map(url => \`<img src="\${url}" />\`).join('\\n');
            break;
        }
        navigator.clipboard.writeText(text).then(() => {
            alert('已复制到剪贴板');
        }).catch(err => {
            alert('复制失败');
        });
      }
    </script>
  </body>
  </html>`;
}

// Generate file management page /admin
function generateAdminPage(fileCards, qrModal, totalFiles, totalSize) {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <link rel="shortcut icon" href="https://pan.811520.xyz/2025-02/1739241502-tgfile-favicon.ico" type="image/x-icon">
  <meta name="description" content="Telegram文件存储与分享平台">
  <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件管理</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        margin: 0;
        padding: 20px;
        background-size: cover;
        background-position: center;
        background-color: #f5f5f5;
        transition: background-image 1s ease-in-out;
      }
      .container {
        max-width: 1200px;
        margin: 0 auto;
      }
      .header {
        background: rgba(255, 255, 255, 0.8);
        padding: 20px 30px;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        margin-bottom: 20px;
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        align-items: center;
      }
      h2 {
        margin: 0;
        text-align: left;
      }
      .stats {
        font-size: 1.2em;
        font-weight: bold;
        color: red;
        margin-left: 20px;
      }
      .actions-container {
        display: flex;
        gap: 15px;
        align-items: center;
        margin-top: 10px;
        width: 100%;
      }
      .search {
        padding: 8px;
        border: 1px solid #ddd;
        border-radius: 4px;
        width: 300px;
        background: rgba(255, 255, 255, 0.5);
      }
      .backup {
        display: inline-block;
        color: #007bff;
        text-decoration: none;
      }
      .backup:hover {
        text-decoration: underline;
      }
      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
        gap: 20px;
      }
      .file-card {
        background: rgba(255, 255, 255, 0.8);
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        overflow: hidden;
        position: relative;
        display: flex;
        flex-direction: column;
      }
      .file-preview {
        height: 150px;
        background: rgba(230, 230, 230, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .file-preview img, .file-preview video {
        max-width: 100%;
        max-height: 100%;
        object-fit: contain;
      }
      .file-info {
        padding: 10px;
        font-size: 14px;
        flex-grow: 1;
        word-break: break-all;
      }
      .password-info {
        cursor: pointer;
        color: #0056b3;
        font-style: italic;
      }
      .file-actions {
        padding: 10px;
        border-top: 1px solid #eee;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 12px;
      }
      .file-checkbox {
        position: absolute;
        left: 10px;
        top: 10px;
        z-index: 10;
        transform: scale(1.5);
      }
      .btn {
        padding: 5px 10px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        text-decoration: none;
        display: inline-block;
        text-align: center;
      }
      .btn-delete {
        background: #dc3545;
        color: white;
      }
      .btn-copy, .btn-down {
        background: #007bff;
        color: white;
      }
      .qr-modal {
        display: none;
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        justify-content: center;
        align-items: center;
        z-index: 1000;
      }
      .qr-content {
        background: white;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
      }
      #qrcode {
        margin: 5px 0;
      }
      .qr-buttons {
        display: flex;
        gap: 10px;
        justify-content: center;
        margin-top: 15px;
      }
      .qr-copy, .qr-close {
        padding: 8px 20px;
        background: #007bff;
        color: white;
        border: none;
        border-radius: 5px;
        cursor: pointer;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h2>文件管理</h2>
        <span class="stats">文件总数: ${totalFiles} | 总大小: ${formatSize(totalSize)}</span>
        <div class="actions-container">
            <input type="checkbox" id="selectAllCheckbox" title="全选">
            <button class="btn btn-delete" id="deleteSelectedBtn">删除选中</button>
            <input type="text" class="search" placeholder="搜索文件..." id="searchInput">
            <a href="/upload" class="backup">返回上传</a>
        </div>
      </div>
      <div class="grid" id="fileGrid">
        ${fileCards}
      </div>
      ${qrModal}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      // Add background image related functions
      async function setBingBackground() {
        try {
          const response = await fetch('/bing', { cache: 'no-store' });  // Disable cache
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) {
          console.error('获取背景图失败:', error);
        }
      }
      // Set background image on page load
      setBingBackground(); 
      // Update background image every hour
      setInterval(setBingBackground, 3600000);

      const searchInput = document.getElementById('searchInput');
      const fileGrid = document.getElementById('fileGrid');
      const fileCards = Array.from(fileGrid.children);

      searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        fileCards.forEach(card => {
          const fileName = card.querySelector('.file-info div:first-child').textContent.toLowerCase();
          card.style.display = fileName.includes(searchTerm) ? '' : 'none';
        });
      });

      // Add QR code sharing function
      let currentShareUrl = '';
      function showQRCode(url) {
        currentShareUrl = url; // Store the current shared URL
        const modal = document.getElementById('qrModal');
        const qrcodeDiv = document.getElementById('qrcode');
        const copyBtn = document.querySelector('.qr-copy');
        copyBtn.textContent = '复制链接';
        copyBtn.disabled = false;
        qrcodeDiv.innerHTML = '';
        new QRCode(qrcodeDiv, {
          text: url,
          width: 200,
          height: 200,
          colorDark: "#000000",
          colorLight: "#ffffff",
          correctLevel: QRCode.CorrectLevel.H
        });
        modal.style.display = 'flex';
      }   

      function handleCopyUrl() {
        navigator.clipboard.writeText(currentShareUrl)
          .then(() => {
            const copyBtn = document.querySelector('.qr-copy');
            copyBtn.textContent = '✔ 已复制';
            copyBtn.disabled = true;
            setTimeout(() => {
              copyBtn.textContent = '复制链接';
              copyBtn.disabled = false;
            }, 5000);
          })
          .catch(err => {
            console.error('复制失败:', err);
            alert('复制失败，请手动复制');
          });
      }

      function closeQRModal() {
        document.getElementById('qrModal').style.display = 'none';
      }      
      window.onclick = function(event) {
        const modal = document.getElementById('qrModal');
        if (event.target === modal) {
          modal.style.display = 'none';
        }
      }

      async function deleteFile(url) {
        if (!confirm('确定要删除这个文件吗？')) return;
        
        try {
          const response = await fetch('/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
          });

          if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || '删除失败');
          }
          
          const card = document.querySelector(\`[data-url="\${url}"]\`);
          if (card) card.remove();
          alert('文件删除成功');
          location.reload(); // Reload to update stats
        } catch (error) {
          alert('文件删除失败: ' + error.message); // Show detailed error message
        }
      }

      function copyToClipboard(text, element) {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = element.innerHTML;
            element.innerHTML = '✔ 已复制!';
            setTimeout(() => {
                element.innerHTML = originalText;
            }, 2000);
        }).catch(err => {
            console.error('复制密码失败:', err);
        });
      }
      
      // Bulk selection and deletion logic
      const selectAllCheckbox = document.getElementById('selectAllCheckbox');
      const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
      const fileCheckboxes = document.querySelectorAll('.file-checkbox');

      selectAllCheckbox.addEventListener('change', (e) => {
        fileCheckboxes.forEach(checkbox => {
            checkbox.checked = e.target.checked;
        });
      });

      deleteSelectedBtn.addEventListener('click', async () => {
        const selectedUrls = Array.from(fileCheckboxes)
            .filter(checkbox => checkbox.checked)
            .map(checkbox => checkbox.closest('.file-card').dataset.url);

        if (selectedUrls.length === 0) {
            alert('请先选择要删除的文件');
            return;
        }

        if (!confirm(\`确定要删除选中的 \${selectedUrls.length} 个文件吗？\n此操作不可逆！\`)) return;

        try {
            const response = await fetch('/delete-multiple', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls: selectedUrls })
            });
            const result = await response.json();
            if (response.ok && result.success) {
                alert('选中的文件已成功删除');
                location.reload();
            } else {
                throw new Error(result.error || '批量删除失败');
            }
        } catch (error) {
            alert('批量删除失败: ' + error.message);
        }
      });
    </script>
  </body>
  </html>`;
}

// Generate password prompt page
function generatePasswordPromptPage(path, error) {
    return `<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>需要密码</title>
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; font-family: sans-serif; background-color: #f0f2f5; }
            .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; }
            input { padding: 10px; margin-top: 10px; border-radius: 4px; border: 1px solid #ccc; width: 200px; }
            button { padding: 10px 20px; margin-top: 10px; border: none; border-radius: 4px; background-color: #007bff; color: white; cursor: pointer; }
            .error { color: red; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>此文件受密码保护</h2>
            <p>请输入密码以继续访问</p>
            <form method="POST" action="${path}">
                <input type="password" name="password" placeholder="请输入密码" required>
                <br>
                <button type="submit">提交</button>
            </form>
            ${error ? `<p class="error">${error}</p>` : ''}
        </div>
    </body>
    </html>`;
}
