// 由于tg的限制，虽然可以上传超过20M的文件，但无法返回直链地址
// 因此修改代码，当文件大于20MB时，直接阻止上传

// 数据库初始化函数
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

// 导出函数
export default {
  async fetch(request, env) {
    // 环境变量配置
    const config = {
      domain: env.DOMAIN,
      database: env.DATABASE,
      username: env.USERNAME,
      password: env.PASSWORD,
      enableAuth: env.ENABLE_AUTH === 'true',
      tgBotToken: env.TG_BOT_TOKEN,
      tgChatId: env.TG_CHAT_ID,
      cookie: Number(env.COOKIE) || 7, // cookie有效期默认为 7
      maxSizeMB: Number(env.MAX_SIZE_MB) || 20 // 上传单文件大小默认为20M
    };

    // 初始化数据库
    await initDatabase(config);
    // 路由处理
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
      '/delete-multiple': () => handleDeleteMultipleRequest(request, config), // 新增批量删除路由
      '/search': () => handleSearchRequest(request, config),
      '/bing': handleBingImagesRequest
    };
    const handler = routes[pathname];
    if (handler) {
      return await handler();
    }
    // 处理文件访问请求
    return await handleFileRequest(request, config);
  }
};

// 处理身份认证
function authenticate(request, config) {
  const cookies = request.headers.get("Cookie") || "";
  const authToken = cookies.match(/auth_token=([^;]+)/); // 获取cookie中的auth_token
  if (authToken) {
    try {
      // 解码token，验证是否过期
      const tokenData = JSON.parse(atob(authToken[1]));
      const now = Date.now();           
      // 检查token是否过期
      if (now > tokenData.expiration) {
        console.log("Token已过期");
        return false;
      }          
      // 如果token有效，返回用户名是否匹配
      return tokenData.username === config.username;
    } catch (error) {
      console.error("Token的用户名不匹配", error);
      return false;
    }
  }
  return false;
}

// 处理路由
async function handleAuthRequest(request, config) {
  if (config.enableAuth) {
    // 使用 authenticate 函数检查用户是否已认证
    const isAuthenticated = authenticate(request, config);
    if (!isAuthenticated) {
      return handleLoginRequest(request, config);  // 认证失败，跳转到登录页面
    }
    return handleUploadRequest(request, config);  // 认证通过，跳转到上传页面
  }
  // 如果没有启用认证，直接跳转到上传页面
  return handleUploadRequest(request, config);
}

// 处理登录
async function handleLoginRequest(request, config) {
  if (request.method === 'POST') {
    const { username, password } = await request.json();
    
    if (username === config.username && password === config.password) {
      // 登录成功，设置一个有效期7天的cookie
      const expirationDate = new Date();
      expirationDate.setDate(expirationDate.getDate() + config.cookie);
      const expirationTimestamp = expirationDate.getTime();
      // 创建token数据，包含用户名和过期时间
      const tokenData = JSON.stringify({
        username: config.username,
        expiration: expirationTimestamp
      });

      const token = btoa(tokenData);  // Base64编码
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
  const html = generateLoginPage();  // 如果是GET请求，返回登录页面
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

// 处理文件上传
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
    const password = formData.get('password') || null; // 获取密码

    if (!file) throw new Error('未找到文件');
    if (file.size > config.maxSizeMB * 1024 * 1024) throw new Error(`文件超过${config.maxSizeMB}MB限制`);
    
    const ext = (file.name.split('.').pop() || '').toLowerCase();  //获取文件扩展名
    const mimeType = getContentType(ext);  // 获取文件类型
    const [mainType] = mimeType.split('/'); // 获取主类型
    // 定义类型映射
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
      password // 存储密码
    ).run();

    return new Response(
      JSON.stringify({ status: 1, msg: "✔ 上传成功", url }),
      { headers: { 'Content-Type': 'application/json' }}
    );

  } catch (error) {
    console.error(`[Upload Error] ${error.message}`);
    // 根据错误信息设定不同的状态码
    let statusCode = 500; // 默认500
    if (error.message.includes(`文件超过${config.maxSizeMB}MB限制`)) {
      statusCode = 400; // 客户端错误：文件大小超限
    } else if (error.message.includes('Telegram参数配置错误')) {
      statusCode = 502; // 网关错误：与Telegram通信失败
    } else if (error.message.includes('未获取到文件ID') || error.message.includes('未获取到tg消息ID')) {
      statusCode = 500; // 服务器内部错误：Telegram返回数据异常
    } else if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
      statusCode = 504; // 网络超时或断网
    }
    return new Response(
      JSON.stringify({ status: 0, msg: "✘ 上传失败", error: error.message }),
      { status: statusCode, headers: { 'Content-Type': 'application/json' }}
    );
  }
}

// 处理文件管理和预览
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
  
  // 统计数据
  const totalFiles = fileList.length;
  const totalSize = fileList.reduce((sum, file) => sum + (file.file_size || 0), 0);

  const fileCards = fileList.map(file => {
    const fileName = file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const passwordInfo = file.password 
      ? `<div>密码: <span class="password" title="点击复制密码" onclick="copyText('${file.password}', this)">${file.password}</span></div>`
      : '<div>密码: 无</div>';

    // 文件预览信息和操作元素
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

  // 二维码分享元素
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

// 处理文件搜索
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

// 支持预览的文件类型
function getPreviewHtml(url) {
  const ext = (url.split('.').pop() || '').toLowerCase();
  const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'].includes(ext);
  const isVideo = ['mp4', 'webm', 'mov', 'avi'].includes(ext);
  const isAudio = ['mp3', 'wav', 'ogg', 'flac'].includes(ext);

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

// 获取文件并缓存
async function handleFileRequest(request, config) {
  const url = new URL(request.url);
  const cache = caches.default;
  const cacheKey = new Request(url.toString());

  try {
    // 尝试从缓存获取
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      console.log(`[Cache Hit] ${url.toString()}`);
      return cachedResponse;
    }

    // 从数据库查询文件
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

    // 检查密码
    if (file.password) {
        const providedPassword = url.searchParams.get('password');
        if (providedPassword !== file.password) {
            return new Response(generatePasswordPromptPage(url.toString()), {
                status: 403,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }

    // 获取 Telegram 文件路径
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

    // 下载文件
    const fileUrl = `https://api.telegram.org/file/bot${config.tgBotToken}/${filePath}`;
    const fileResponse = await fetch(fileUrl);

    if (!fileResponse.ok) {
      console.error(`[Download Error] Failed to download from ${fileUrl}`);
      return new Response('下载文件失败', { 
        status: 500,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }

    // 使用存储的 MIME 类型或根据扩展名判断
    const contentType = file.mime_type || getContentType(url.pathname.split('.').pop().toLowerCase());

    // 创建响应并缓存
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

// 处理文件删除
async function handleDeleteRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
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

    // 删除数据库表数据，即使Telegram删除失败也会删除数据库记录
    await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
    
    // 从缓存中删除
    await caches.default.delete(new Request(url));

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

// 处理批量删除
async function handleDeleteMultipleRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
    }

    try {
        const { urls } = await request.json();
        if (!Array.isArray(urls) || urls.length === 0) {
            return new Response(JSON.stringify({ error: '无效的URL列表' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        let successCount = 0;
        let failedCount = 0;
        const errors = [];

        for (const url of urls) {
            try {
                const file = await config.database.prepare('SELECT message_id FROM files WHERE url = ?').bind(url).first();
                if (file) {
                    await fetch(`https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`);
                    await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
                    await caches.default.delete(new Request(url));
                }
                successCount++;
            } catch (e) {
                failedCount++;
                errors.push(`删除 ${url} 失败: ${e.message}`);
                console.error(`[Multiple Delete Error] ${url}: ${e.message}`);
            }
        }

        return new Response(JSON.stringify({
            success: true,
            message: `成功删除 ${successCount} 个文件，失败 ${failedCount} 个。`,
            errors
        }), { headers: { 'Content-Type': 'application/json' } });

    } catch (error) {
        console.error(`[Batch Delete Error] ${error.message}`);
        return new Response(JSON.stringify({ error: '批量删除过程中发生服务器错误' }), { status: 500 });
    }
}

// 支持上传的文件类型 (支持任意格式)
function getContentType(ext) {
  const types = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/x-icon',
    mp4: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime', avi: 'video/x-msvideo',
    mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg', flac: 'audio/flac',
    pdf: 'application/pdf', txt: 'text/plain', md: 'text/markdown',
    zip: 'application/zip', rar: 'application/x-rar-compressed', '7z': 'application/x-7z-compressed',
    json: 'application/json', xml: 'application/xml', ini: 'text/plain',
    js: 'application/javascript', css: 'text/css', html: 'text/html',
    yml: 'application/yaml', yaml: 'application/yaml',
    py: 'text/x-python', sh: 'application/x-sh',
    doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
  };
  return types[ext] || 'application/octet-stream';
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

// 文件大小计算函数
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}

// 登录页面生成函数 /login
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
      }
      .login-container {
        background: rgba(255, 255, 255, 0.8);
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        width: 100%;
        max-width: 400px;
        backdrop-filter: blur(5px);
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
      async function setBingBackground() {
        try {
          const response = await fetch('/bing', { cache: 'no-store' });
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) {
          console.error('获取背景图失败:', error);
        }
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
          console.error('登录失败:', err);
          document.getElementById('error').style.display = 'block';
        }
      });
    </script>
  </body>
  </html>`;
}

// 生成文件上传页面 /upload
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
        margin: 0 auto 20px auto;
        border-radius: 8px;
        transition: all 0.3s;
        box-sizing: border-box;
      }
      .upload-area.dragover {
        border-color: #007bff;
        background: #f8f9fa;
      }
      #password-input {
        width: 100%;
        padding: 10px;
        margin-bottom: 20px;
        border: 1px solid #ddd;
        border-radius: 4px;
        box-sizing: border-box;
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
        text-shadow: 1px 1px 1px rgba(0,0,0,0.5);
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
        <p>点击选择 或 拖拽文件到此处</p>
        <input type="file" id="fileInput" multiple style="display: none">
      </div>
      <input type="text" id="password-input" placeholder="可选：为文件链接设置访问密码">
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
      async function setBingBackground() {
        try {
          const response = await fetch('/bing', { cache: 'no-store' });
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) {
          console.error('获取背景图失败:', error);
        }
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
        if (passwordInput.value) {
            formData.append('password', passwordInput.value);
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
        const units = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return \`\${(bytes / Math.pow(1024, i)).toFixed(2)} \${units[i]}\`;
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
        navigator.clipboard.writeText(text);
        alert('已复制到剪贴板');
      }
    </script>
  </body>
  </html>`;
}

// 生成文件管理页面 /admin
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
        background-attachment: fixed;
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
        gap: 15px;
        backdrop-filter: blur(5px);
      }
      h2 {
        margin: 0;
      }
      .stats {
        color: red;
        font-weight: bold;
        font-size: 1.2em;
      }
      .actions-group {
        display: flex;
        align-items: center;
        gap: 10px;
      }
      .search {
        padding: 8px;
        border: 1px solid #ddd;
        border-radius: 4px;
        width: 250px;
        background: rgba(255, 255, 255, 0.5);
      }
      .btn-header {
        padding: 8px 12px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        color: white;
      }
      .btn-delete-selected { background: #dc3545; }
      .btn-back { background: #007bff; text-decoration: none; }

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
        backdrop-filter: blur(5px);
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
        word-break: break-all;
      }
      .file-info > div {
        margin-bottom: 5px;
      }
      .password {
        cursor: pointer;
        background: #eee;
        padding: 2px 4px;
        border-radius: 3px;
        font-family: monospace;
      }
      .password:hover { background: #ddd; }
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
        width: 18px;
        height: 18px;
      }
      .btn {
        padding: 5px 10px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: inherit;
      }
      .btn-delete { background: #dc3545; color: white; }
      .btn-copy { background: #007bff; color: white; }
      .btn-down { background: #28a745; color: white; text-decoration: none; }
      .qr-modal {
        display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        background: rgba(0, 0, 0, 0.5); justify-content: center; align-items: center; z-index: 1000;
      }
      .qr-content { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.2); }
      #qrcode { margin: 5px 0; }
      .qr-buttons { display: flex; gap: 10px; justify-content: center; margin-top: 15px; }
      .qr-copy, .qr-close { padding: 8px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h2>文件管理</h2>
        <div class="stats">文件总数: ${totalFiles}, 总大小: ${formatSize(totalSize)}</div>
        <div class="actions-group">
            <label><input type="checkbox" id="selectAllCheckbox"> 全选</label>
            <button class="btn-header btn-delete-selected" id="deleteSelectedBtn">删除选中</button>
            <input type="text" class="search" placeholder="搜索文件名..." id="searchInput">
            <a href="/upload" class="btn-header btn-back">返回上传</a>
        </div>
      </div>
      <div class="grid" id="fileGrid">
        ${fileCards}
      </div>
      ${qrModal}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      async function setBingBackground() {
        try {
          const response = await fetch('/bing', { cache: 'no-store' });
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
          }
        } catch (error) { console.error('获取背景图失败:', error); }
      }
      setBingBackground(); 
      setInterval(setBingBackground, 3600000);

      const searchInput = document.getElementById('searchInput');
      const fileGrid = document.getElementById('fileGrid');
      const fileCards = Array.from(fileGrid.children);
      const selectAllCheckbox = document.getElementById('selectAllCheckbox');
      const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');

      searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        fileCards.forEach(card => {
          const fileName = card.querySelector('.file-info > div:first-child').textContent.toLowerCase();
          card.style.display = fileName.includes(searchTerm) ? '' : 'none';
        });
      });

      selectAllCheckbox.addEventListener('change', (e) => {
        const isChecked = e.target.checked;
        document.querySelectorAll('.file-checkbox').forEach(checkbox => {
            checkbox.checked = isChecked;
        });
      });

      deleteSelectedBtn.addEventListener('click', async () => {
        const selectedCheckboxes = document.querySelectorAll('.file-checkbox:checked');
        if (selectedCheckboxes.length === 0) {
            alert('请先选择要删除的文件');
            return;
        }
        if (!confirm(\`确定要删除选中的 \${selectedCheckboxes.length} 个文件吗？\')) return;

        const urlsToDelete = Array.from(selectedCheckboxes).map(cb => cb.closest('.file-card').dataset.url);
        
        try {
            const response = await fetch('/delete-multiple', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls: urlsToDelete })
            });
            const result = await response.json();
            alert(result.message || '操作完成');
            urlsToDelete.forEach(url => {
                const card = document.querySelector(\`[data-url="\${url}"]\`);
                if (card) card.remove();
            });
            // 刷新页面以更新统计信息
            window.location.reload();
        } catch (error) {
            alert('批量删除失败: ' + error.message);
        }
      });

      let currentShareUrl = '';
      function showQRCode(url) {
        currentShareUrl = url;
        const modal = document.getElementById('qrModal');
        const qrcodeDiv = document.getElementById('qrcode');
        qrcodeDiv.innerHTML = '';
        new QRCode(qrcodeDiv, { text: url, width: 200, height: 200 });
        modal.style.display = 'flex';
      }   

      function handleCopyUrl() {
        copyText(currentShareUrl, document.querySelector('.qr-copy'));
      }
      
      function copyText(text, element) {
        navigator.clipboard.writeText(text).then(() => {
            if (element) {
                const originalText = element.textContent;
                element.textContent = '✔ 已复制';
                element.disabled = true;
                setTimeout(() => {
                    element.textContent = originalText;
                    element.disabled = false;
                }, 2000);
            } else {
                alert('已复制到剪贴板');
            }
        }).catch(err => alert('复制失败'));
      }

      function closeQRModal() { document.getElementById('qrModal').style.display = 'none'; }      
      window.onclick = (event) => {
        const modal = document.getElementById('qrModal');
        if (event.target === modal) modal.style.display = 'none';
      }

      async function deleteFile(url) {
        if (!confirm('确定要删除这个文件吗？')) return;
        
        try {
          const response = await fetch('/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
          });
          const result = await response.json();
          if (!response.ok) throw new Error(result.error || '删除失败');
          
          const card = document.querySelector(\`[data-url="\${url}"]\`);
          if (card) card.remove();
          alert(result.message || '文件删除成功');
          window.location.reload();
        } catch (error) {
          alert('文件删除失败: ' + error.message);
        }
      }
    </script>
  </body>
  </html>`;
}

function generatePasswordPromptPage(url) {
    return `<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>需要密码</title>
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; font-family: Arial, sans-serif; background: #f0f2f5; }
            .prompt-container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); text-align: center; }
            h2 { margin-bottom: 20px; }
            input { width: 100%; padding: 10px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <div class="prompt-container">
            <h2>请输入密码访问文件</h2>
            <form action="${url}" method="GET">
                <input type="password" name="password" placeholder="请输入密码" required>
                <button type="submit">确认</button>
            </form>
        </div>
    </body>
    </html>`;
}
