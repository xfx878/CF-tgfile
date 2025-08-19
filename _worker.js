// Due to Telegram's limitations, although files over 20M can be uploaded, a direct link address cannot be returned.
// Therefore, the code is modified to prevent uploads if the file is larger than 20MB.

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
      '/edit': () => handleEditRequest(request, config), // New endpoint for editing file info
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
  const authToken = cookies.match(/auth_token=([^;]+)/); // get auth_token from cookie
  if (authToken) {
    try {
      // decode token, verify expiration
      const tokenData = JSON.parse(atob(authToken[1]));
      const now = Date.now();           
      // check if token has expired
      if (now > tokenData.expiration) {
        console.log("Token has expired");
        return false;
      }          
      // if token is valid, return whether username matches
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
      return handleLoginRequest(request, config);  // authentication failed, redirect to login page
    }
    return handleUploadRequest(request, config);  // authentication successful, redirect to upload page
  }
  // If authentication is not enabled, redirect directly to upload page
  return handleUploadRequest(request, config);
}

// Handle login
async function handleLoginRequest(request, config) {
  if (request.method === 'POST') {
    const { username, password } = await request.json();
    
    if (username === config.username && password === config.password) {
      // login successful, set a cookie valid for 7 days
      const expirationDate = new Date();
      expirationDate.setDate(expirationDate.getDate() + config.cookie);
      const expirationTimestamp = expirationDate.getTime();
      // create token data, including username and expiration time
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
  const html = generateLoginPage();  // if it's a GET request, return the login page
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
    const password = formData.get('password') || null; // Get password, default to null if not provided
    if (!file) throw new Error('未找到文件');
    if (file.size > config.maxSizeMB * 1024 * 1024) throw new Error(`文件超过${config.maxSizeMB}MB限制`);
    
    const ext = (file.name.split('.').pop() || '').toLowerCase();  //get file extension
    const mimeType = getContentType(ext);  // get file type
    const [mainType] = mimeType.split('/'); // get main type
    // define type mapping
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
      password // Store password in the database
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

  const files = await config.database.prepare(
    `SELECT url, fileId, message_id, created_at, file_name, file_size, mime_type, password
    FROM files
    ORDER BY created_at DESC`
  ).all();

  const fileList = files.results || [];
  const totalFiles = fileList.length;

  const fileCards = fileList.map(file => {
    const fileName = file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const passwordDisplay = file.password ? '●●●●●●' : '无';
    // File preview information and action elements
    return `
      <div class="file-card" data-url="${file.url}">
        <input type="checkbox" class="file-checkbox">
        <div class="file-preview">
          ${getPreviewHtml(file.url)}
        </div>
        <div class="file-info">
          <div class="file-name" title="${fileName}">${fileName}</div>
          <div>${fileSize}</div>
          <div class="file-password" title="点击复制密码" onclick="copyPassword('${file.password || ''}')">密码: ${passwordDisplay}</div>
          <div>${createdAt}</div>
        </div>
        <div class="file-actions">
          <button class="btn btn-copy" onclick="showQRCode('${file.url}')">分享</button>
          <button class="btn btn-edit" onclick="openEditModal('${file.url}', '${fileName}', '${file.password || ''}')">编辑</button>
          <a class="btn btn-down" href="${file.url}" download="${fileName}">下载</a>
          <button class="btn btn-delete" onclick="deleteFile('${file.url}')">删除</button>
        </div>
      </div>
    `;
  }).join('');

  // QR code sharing element
  const qrModal = `
    <div id="qrModal" class="modal">
      <div class="modal-content">
        <div id="qrcode"></div>
        <div class="share-link-container">
            <a id="shareLink" href="#" target="_blank"></a>
            <button class="btn-copy-link" onclick="handleCopyUrl()">复制</button>
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
                <button class="btn-save" onclick="saveFileChanges()">保存</button>
                <button class="modal-close" onclick="closeModal('editModal')">取消</button>
            </div>
        </div>
    </div>
  `;


  const html = generateAdminPage(fileCards, qrModal, editModal, totalFiles);
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

// Handle file editing
async function handleEditRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
    }

    try {
        const { url, fileName, password } = await request.json();
        if (!url || !fileName) {
            return new Response(JSON.stringify({ error: '无效的请求' }), { status: 400 });
        }

        await config.database.prepare(
            'UPDATE files SET file_name = ?, password = ? WHERE url = ?'
        ).bind(fileName, password || null, url).run();

        return new Response(JSON.stringify({ success: true, message: '文件信息更新成功' }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error(`[Edit Error] ${error.message}`);
        return new Response(JSON.stringify({ error: '更新失败' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
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
  const isVideo = ['mp4', 'webm', 'mov'].includes(ext);
  const isAudio = ['mp3', 'wav', 'ogg', 'flac'].includes(ext);

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

    // Password check logic
    if (file.password) {
      if (request.method === 'POST') {
        const formData = await request.formData();
        if (formData.get('password') === file.password) {
          // Password correct, proceed to serve file
        } else {
          return new Response(generatePasswordPromptPage(url.toString(), '密码错误'), {
            status: 401,
            headers: { 'Content-Type': 'text/html;charset=UTF-8' }
          });
        }
      } else {
        return new Response(generatePasswordPromptPage(url.toString()), {
          headers: { 'Content-Type': 'text/html;charset=UTF-8' }
        });
      }
    }

    const tgResponse = await fetch(
      `https://api.telegram.org/bot${config.tgBotToken}/getFile?file_id=${file.fileId}`
    );
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

    const response = new Response(fileResponse.body, {
      headers: {
        'Content-Type': file.mime_type || getContentType(url.pathname.split('.').pop().toLowerCase()),
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

    let successes = 0;
    let failures = 0;
    let errors = [];

    for (const url of urls) {
      const file = await config.database.prepare(
        'SELECT message_id FROM files WHERE url = ?'
      ).bind(url).first();
      
      if (!file) {
        failures++;
        errors.push(`URL ${url} not found.`);
        continue;
      }

      try {
        const deleteResponse = await fetch(
          `https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`
        );
        if (!deleteResponse.ok) {
            // Even if TG deletion fails, we continue to delete from DB
        }
      } catch (e) {
        // Network error, also continue
      }
      
      await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
      successes++;
    }

    return new Response(
      JSON.stringify({ 
        success: true,
        message: `删除完成: ${successes} 个成功, ${failures} 个失败.`,
        errors
      }),
      { headers: { 'Content-Type': 'application/json' }}
    );

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(JSON.stringify({ error: '删除操作失败' }), { status: 500 });
  }
}

// Supported upload file types
function getContentType(ext) {
  const types = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/x-icon',
    mp4: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime',
    mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg', flac: 'audio/flac',
    pdf: 'application/pdf', txt: 'text/plain', md: 'text/markdown',
    zip: 'application/zip', rar: 'application/x-rar-compressed', '7z': 'application/x-7z-compressed',
    json: 'application/json', xml: 'application/xml',
    js: 'application/javascript', css: 'text/css', html: 'text/html',
    doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    apk: 'application/vnd.android.package-archive',
  };
  return types[ext] || 'application/octet-stream';
}

async function handleBingImagesRequest(request, config) {
  const cache = caches.default;
  const cacheKey = new Request('https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=5');
  
  const cachedResponse = await cache.match(cacheKey);
  if (cachedResponse) {
    return cachedResponse;
  }
  
  try {
    const res = await fetch(cacheKey);
    if (!res.ok) {
      return new Response('请求 Bing API 失败', { status: res.status });
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
    return new Response('请求 Bing API 失败', { status: 500 });
  }
}

// File size calculation function
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}


// Login page generation function /login
function generateLoginPage() {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录</title>
    <style>
      body { display: flex; justify-content: center; align-items: center; height: 100vh; background-size: cover; background-position: center; font-family: Arial, sans-serif; transition: background-image 1s ease-in-out; }
      .login-container { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }
      h2 { text-align: center; margin-bottom: 2rem; }
      .form-group { margin-bottom: 1.5rem; }
      input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; box-sizing: border-box; }
      button { width: 100%; padding: 0.75rem; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
      button:hover { background: #0056b3; }
      .error { color: #dc3545; margin-top: 1rem; text-align: center; display: none; }
    </style>
  </head>
  <body>
    <div class="login-container">
      <h2>登录</h2>
      <form id="loginForm">
        <div class="form-group"><input type="text" id="username" placeholder="用户名" required></div>
        <div class="form-group"><input type="password" id="password" placeholder="密码" required></div>
        <button type="submit">登录</button>
        <div id="error" class="error">用户名或密码错误</div>
      </form>
    </div>
    <script>
      (async function() {
        try {
          const response = await fetch('/bing');
          const data = await response.json();
          if (data.status && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) { console.error('获取背景图失败:', error); }
      })();
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
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件上传</title>
    <style>
      body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-size: cover; background-position: center; margin: 0; transition: background-image 1s ease-in-out; }
      .container { max-width: 800px; width: 90%; background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 20px 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.2); overflow-y: auto; max-height: 90vh; }
      .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
      .upload-area { border: 2px dashed #007bff; padding: 40px; text-align: center; border-radius: 8px; cursor: pointer; transition: all 0.3s; }
      .upload-area.dragover { border-color: #0056b3; background: rgba(0, 123, 255, 0.1); }
      #password-container { margin-top: 15px; }
      #filePassword { width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc; box-sizing: border-box; }
      .preview-area { margin-top: 20px; }
      .preview-item { display: flex; align-items: center; padding: 10px; border: 1px solid #ddd; margin-bottom: 10px; border-radius: 4px; }
      .preview-item img { max-width: 80px; max-height: 80px; margin-right: 15px; object-fit: cover; }
      .preview-item .info { flex-grow: 1; }
      .url-area { margin-top: 20px; }
      .url-area textarea { width: 100%; min-height: 100px; padding: 10px; border-radius: 4px; border: 1px solid #ddd; box-sizing: border-box; }
      .button-group { margin-top: 10px; display: flex; justify-content: space-between; align-items: center; }
      .button-container button { margin-right: 10px; padding: 8px 12px; border: none; border-radius: 4px; background: #007bff; color: white; cursor: pointer; }
      .button-container button:hover { background: #0056b3; }
      .progress-bar { height: 10px; background: #eee; border-radius: 5px; margin-top: 8px; overflow: hidden; position: relative; }
      .progress-track { height: 100%; background: #007bff; transition: width 0.3s ease; width: 0; }
      .progress-text { position: absolute; width: 100%; text-align: center; top: -5px; color: #333; font-size: 12px; line-height: 20px; }
      .success .progress-track { background: #28a745; }
      .error .progress-track { background: #dc3545; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header"><h1>文件上传</h1><a href="/admin">文件管理</a></div>
      <div class="upload-area" id="uploadArea">
        <p>点击或拖拽文件到此处</p>
        <input type="file" id="fileInput" multiple style="display: none">
      </div>
      <div id="password-container">
        <input type="password" id="filePassword" placeholder="可选：为文件设置访问密码">
      </div>
      <div class="preview-area" id="previewArea"></div>
      <div class="url-area">
        <textarea id="urlArea" readonly placeholder="上传链接将显示在这里"></textarea>
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
      (async function() {
        try {
          const response = await fetch('/bing');
          const data = await response.json();
          if (data.status && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) { console.error('获取背景图失败:', error); }
      })();

      const uploadArea = document.getElementById('uploadArea');
      const fileInput = document.getElementById('fileInput');
      const previewArea = document.getElementById('previewArea');
      const urlArea = document.getElementById('urlArea');
      let uploadedUrls = [];

      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, e => { e.preventDefault(); e.stopPropagation(); }, false);
      });
      ['dragenter', 'dragover'].forEach(eventName => uploadArea.addEventListener(eventName, () => uploadArea.classList.add('dragover'), false));
      ['dragleave', 'drop'].forEach(eventName => uploadArea.addEventListener(eventName, () => uploadArea.classList.remove('dragover'), false));

      uploadArea.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', (e) => handleFiles(e.target.files));
      uploadArea.addEventListener('drop', (e) => handleFiles(e.dataTransfer.files), false);
      document.addEventListener('paste', e => {
          const items = (e.clipboardData || e.originalEvent.clipboardData).items;
          const files = [];
          for (const item of items) {
              if (item.kind === 'file') files.push(item.getAsFile());
          }
          if (files.length > 0) handleFiles(files);
      });

      async function handleFiles(files) {
        const config = await (await fetch('/config')).json();
        for (let file of files) {
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
        formData.append('password', document.getElementById('filePassword').value);
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
      function formatSize(bytes) {
          if (bytes === 0) return '0 B';
          const units = ['B', 'KB', 'MB', 'GB'];
          const i = Math.floor(Math.log(bytes) / Math.log(1024));
          return \`\${(bytes / Math.pow(1024, i)).toFixed(2)} \${units[i]}\`;
      }
      function updateUrlArea() { urlArea.value = uploadedUrls.join('\\n'); }
      function copyUrls(format) {
        let text = '';
        switch (format) {
          case 'url': text = uploadedUrls.join('\\n'); break;
          case 'markdown': text = uploadedUrls.map(url => \`![](\${url})\`).join('\\n'); break;
          case 'html': text = uploadedUrls.map(url => \`<img src="\${url}">\`).join('\\n'); break;
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
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件管理</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-size: cover; background-position: center; background-attachment: fixed; transition: background-image 1s ease-in-out; }
      .container { max-width: 1400px; margin: 0 auto; }
      .header { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 20px 30px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.2); margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
      .controls { display: flex; align-items: center; gap: 20px; }
      .stats { font-size: 1.1em; }
      .search { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 250px; }
      .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 20px; }
      .file-card { background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(5px); border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; position: relative; display: flex; flex-direction: column; }
      .file-preview { height: 150px; display: flex; align-items: center; justify-content: center; background: #f0f0f0; }
      .file-preview img, .file-preview video { max-width: 100%; max-height: 100%; object-fit: contain; }
      .file-info { padding: 10px; font-size: 14px; flex-grow: 1; }
      .file-name { font-weight: bold; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .file-password { cursor: pointer; }
      .file-actions { padding: 10px; border-top: 1px solid #eee; display: grid; grid-template-columns: repeat(2, 1fr); gap: 5px; }
      .file-checkbox { position: absolute; left: 10px; top: 10px; z-index: 10; transform: scale(1.2); }
      .btn, .btn-down { padding: 8px 10px; border: none; border-radius: 4px; cursor: pointer; text-align: center; text-decoration: none; color: white; }
      .btn-delete { background: #dc3545; } .btn-copy { background: #007bff; } .btn-edit { background: #ffc107; color: #333; } .btn-down { background: #17a2b8; }
      .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); justify-content: center; align-items: center; z-index: 1000; }
      .modal-content { background: white; padding: 30px; border-radius: 10px; text-align: center; box-shadow: 0 5px 25px rgba(0,0,0,0.3); }
      #qrcode { margin: 20px 0; }
      .share-link-container { display: flex; align-items: center; justify-content: center; margin-top: 10px; gap: 10px; }
      #shareLink { color: #007bff; text-decoration: none; }
      .modal-close, .btn-save, .btn-copy-link { padding: 8px 20px; border: none; border-radius: 5px; cursor: pointer; }
      .modal-close { background: #6c757d; color: white; margin-top: 20px; } .btn-save { background: #28a745; color: white; }
      #editModal .form-group { margin-bottom: 15px; text-align: left; }
      #editModal input { width: 100%; padding: 8px; box-sizing: border-box; }
      #editModal .modal-buttons { display: flex; gap: 10px; justify-content: center; margin-top: 20px; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h2>文件管理</h2>
        <div class="controls">
            <div class="stats">文件总数: <span style="color: red; font-weight: bold; font-size: 1.2em;">${totalFiles}</span></div>
            <div><input type="checkbox" id="selectAllCheckbox"> 全选</div>
            <button id="deleteSelectedBtn" class="btn btn-delete">删除选中</button>
            <input type="text" class="search" placeholder="搜索文件名..." id="searchInput">
            <a href="/upload">返回上传</a>
        </div>
      </div>
      <div class="grid" id="fileGrid">${fileCards}</div>
      ${qrModal}
      ${editModal}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      (async function() {
        try {
          const response = await fetch('/bing');
          const data = await response.json();
          if (data.status && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) { console.error('获取背景图失败:', error); }
      })();

      const searchInput = document.getElementById('searchInput');
      const fileGrid = document.getElementById('fileGrid');
      
      searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        Array.from(fileGrid.children).forEach(card => {
          const fileName = card.querySelector('.file-name').textContent.toLowerCase();
          card.style.display = fileName.includes(searchTerm) ? '' : 'flex';
        });
      });

      document.getElementById('selectAllCheckbox').addEventListener('change', e => {
          document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = e.target.checked);
      });

      document.getElementById('deleteSelectedBtn').addEventListener('click', async () => {
          const selectedUrls = Array.from(document.querySelectorAll('.file-checkbox:checked'))
                                    .map(cb => cb.closest('.file-card').dataset.url);
          if (selectedUrls.length === 0) return alert('请先选择要删除的文件');
          if (!confirm(\`确定要删除选中的 \${selectedUrls.length} 个文件吗？\`)) return;
          
          try {
              const response = await fetch('/delete', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ urls: selectedUrls })
              });
              const result = await response.json();
              if (result.success) {
                  alert(result.message);
                  window.location.reload();
              } else {
                  throw new Error(result.error || '删除失败');
              }
          } catch (error) {
              alert('删除失败: ' + error.message);
          }
      });

      let currentShareUrl = '';
      function showQRCode(url) {
        currentShareUrl = url;
        const modal = document.getElementById('qrModal');
        const qrcodeDiv = document.getElementById('qrcode');
        qrcodeDiv.innerHTML = '';
        new QRCode(qrcodeDiv, { text: url, width: 200, height: 200 });
        const shareLink = document.getElementById('shareLink');
        shareLink.href = url;
        shareLink.textContent = url;
        modal.style.display = 'flex';
      }

      function handleCopyUrl() {
        navigator.clipboard.writeText(currentShareUrl).then(() => alert('链接已复制'));
      }

      function closeModal(modalId) { document.getElementById(modalId).style.display = 'none'; }
      
      window.onclick = function(event) {
        if (event.target.classList.contains('modal')) {
          event.target.style.display = 'none';
        }
      }

      async function deleteFile(url) {
        if (!confirm('确定要删除这个文件吗？')) return;
        try {
          const response = await fetch('/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls: [url] })
          });
          const result = await response.json();
          if (result.success) {
            document.querySelector(\`[data-url="\${url}"]\`).remove();
            alert('文件删除成功');
          } else { throw new Error(result.error); }
        } catch (error) {
          alert('文件删除失败: ' + error.message);
        }
      }

      function copyPassword(password) {
          if (!password) return;
          navigator.clipboard.writeText(password).then(() => alert('密码已复制'));
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
              const response = await fetch('/edit', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ url, fileName, password })
              });
              const result = await response.json();
              if (result.success) {
                  alert('更新成功');
                  window.location.reload();
              } else {
                  throw new Error(result.error);
              }
          } catch (error) {
              alert('更新失败: ' + error.message);
          }
      }
    </script>
  </body>
  </html>`;
}

function generatePasswordPromptPage(url, error = '') {
    return `<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>需要密码</title>
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; font-family: Arial, sans-serif; background: #f0f2f5; }
            .prompt-container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center; }
            input { padding: 10px; margin-top: 10px; border-radius: 4px; border: 1px solid #ccc; }
            button { padding: 10px 20px; margin-left: 10px; border: none; border-radius: 4px; background: #007bff; color: white; cursor: pointer; }
            .error { color: red; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="prompt-container">
            <h3>此文件需要密码才能访问</h3>
            <form method="POST" action="${url}">
                <input type="password" name="password" placeholder="请输入密码" required>
                <button type="submit">提交</button>
            </form>
            ${error ? `<p class="error">${error}</p>` : ''}
        </div>
    </body>
    </html>`;
}
