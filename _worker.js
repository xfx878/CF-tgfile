// 数据库初始化函数
// 新增: 添加 password 字段用于存储文件密码
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
      '/search': () => handleSearchRequest(request, config),
      '/update': () => handleUpdateRequest(request, config), // 新增: 编辑文件信息路由
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
    const password = formData.get('password'); // 新增: 获取密码
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
    
    // 新增: 在INSERT语句中加入 password
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
      password || null // 如果密码为空则存为NULL
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

  // 新增: 查询时获取 password 字段
  const files = await config.database.prepare(
    `SELECT url, fileId, message_id, created_at, file_name, file_size, mime_type, password
    FROM files
    ORDER BY created_at DESC`
  ).all();

  const fileList = files.results || [];
  
  // 计算文件总数和总大小
  const totalFiles = fileList.length;
  const totalSize = fileList.reduce((sum, file) => sum + (file.file_size || 0), 0);
  const stats = {
    count: totalFiles,
    size: formatSize(totalSize)
  };

  const fileCards = fileList.map(file => {
    const fileName = file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const hasPassword = file.password && file.password.length > 0;
    
    // 新增: 
    // 1. 在卡片上添加 data-filename 和 data-password 属性，用于编辑功能
    // 2. 显示密码信息，并添加点击复制功能
    // 3. 在分享按钮右侧添加编辑按钮
    return `
      <div class="file-card" data-url="${file.url}" data-filename="${file.file_name}" data-password="${file.password || ''}">
        <input type="checkbox" class="file-checkbox">
        <div class="file-preview">
          ${getPreviewHtml(file.url)}
        </div>
        <div class="file-info">
          <div class="file-name">${fileName}</div>
          ${hasPassword ? `<div class="file-password" onclick="copyPassword('${file.password}', this)">密码: *** (点击复制)</div>` : '<div class="file-password" style="cursor: default;">无密码</div>'}
          <div class="file-meta">${fileSize}</div>
          <div class="file-meta">${createdAt}</div>
        </div>
        <div class="file-actions">
          <button class="btn btn-copy" onclick="showQRCode('${file.url}')">分享</button>
          <button class="btn btn-edit" onclick="showEditModal('${file.url}')">编辑</button>
          <a class="btn btn-down" href="${file.url}" download="${fileName}">下载</a>
          <button class="btn btn-delete" onclick="deleteFile('${file.url}')">删除</button>
        </div>
      </div>
    `;
  }).join('');

  // 新增: 
  // 1. 二维码下方添加链接显示区域
  // 2. 编辑文件信息的弹窗
  const modals = `
    <div id="qrModal" class="modal-overlay">
      <div class="modal-content">
        <div id="qrcode"></div>
        <div id="qrLinkContainer">
          <a id="qrLink" href="#" target="_blank"></a>
        </div>
        <div class="modal-buttons">
          <button class="btn" onclick="handleCopyUrl()">复制链接</button>
          <button class="btn btn-close" onclick="closeAllModals()">关闭</button>
        </div>
      </div>
    </div>
    <div id="editModal" class="modal-overlay">
        <div class="modal-content">
            <h3>编辑文件信息</h3>
            <input type="hidden" id="editFileUrl">
            <div class="form-group">
                <label for="editFileName">文件名:</label>
                <input type="text" id="editFileName">
            </div>
            <div class="form-group">
                <label for="editFilePassword">密码:</label>
                <input type="text" id="editFilePassword" placeholder="留空则无密码">
            </div>
            <div class="modal-buttons">
                <button class="btn" onclick="saveFileChanges()">保存</button>
                <button class="btn btn-close" onclick="closeAllModals()">取消</button>
            </div>
        </div>
    </div>
  `;

  const html = generateAdminPage(fileCards, modals, stats);
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
    // 新增: 查询时获取 password 字段
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
  const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'icon'].includes(ext);
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

// 获取文件并缓存
async function handleFileRequest(request, config) {
  const url = request.url.split('?')[0]; // 忽略查询参数进行匹配
  const cache = caches.default;
  const cacheKey = new Request(url);

  try {
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      console.log(`[Cache Hit] ${url}`);
      return cachedResponse;
    }

    // 新增: 查询时获取 password 字段
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

    // 新增: 密码验证逻辑
    if (file.password) {
        let authorized = false;
        const requestUrl = new URL(request.url);
        const providedPasswordQuery = requestUrl.searchParams.get('pwd');

        if (request.method === 'POST') {
            const formData = await request.formData();
            if (formData.get('password') === file.password) {
                authorized = true;
            } else {
                return new Response(generatePasswordPromptPage(true), { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
            }
        } else if (providedPasswordQuery === file.password) {
            authorized = true;
        }

        if (!authorized) {
            return new Response(generatePasswordPromptPage(false), { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
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

    const contentType = file.mime_type || getContentType(url.split('.').pop().toLowerCase());

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

// 处理文件删除
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

    const results = [];
    for (const url of urls) {
      const file = await config.database.prepare(
        'SELECT fileId, message_id FROM files WHERE url = ?'
      ).bind(url).first();

      if (!file) {
        results.push({ url, success: false, error: '文件不存在' });
        continue;
      }

      let deleteError = null;
      try {
        const deleteResponse = await fetch(
          `https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`
        );
        if (!deleteResponse.ok) {
          const errorData = await deleteResponse.json();
          throw new Error(errorData.description || 'Telegram API 错误');
        }
      } catch (error) {
        deleteError = error.message;
      }

      await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();

      if (deleteError) {
        results.push({ url, success: true, message: `数据库记录已删除，但TG消息删除失败: ${deleteError}` });
      } else {
        results.push({ url, success: true, message: '文件删除成功' });
      }
    }
    
    return new Response(JSON.stringify({ results }), {
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 500, headers: { 'Content-Type': 'application/json' }}
    );
  }
}

// 新增: 处理文件信息更新的函数
async function handleUpdateRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ success: false, error: '未授权' }), { status: 401 });
  }

  try {
    const { url, fileName, password } = await request.json();
    if (!url || !fileName) {
      return new Response(JSON.stringify({ success: false, error: '缺少必要参数' }), { status: 400 });
    }

    const result = await config.database.prepare(
      'UPDATE files SET file_name = ?, password = ? WHERE url = ?'
    ).bind(fileName, password || null, url).run();

    if (result.meta.changes > 0) {
      return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
    } else {
      return new Response(JSON.stringify({ success: false, error: '未找到文件或无需更新' }), { status: 404 });
    }
  } catch (error) {
    console.error(`[Update Error] ${error.message}`);
    return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500 });
  }
}

// 支持上传的文件类型
function getContentType(ext) {
  const types = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', icon: 'image/x-icon',
    mp4: 'video/mp4', webm: 'video/webm',
    mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg',
    pdf: 'application/pdf', txt: 'text/plain', md: 'text/markdown',
    zip: 'application/zip', rar: 'application/x-rar-compressed',
    json: 'application/json', xml: 'application/xml', ini: 'text/plain',
    js: 'application/javascript', yml: 'application/yaml', yaml: 'application/yaml',
    py: 'text/x-python', sh: 'application/x-sh',
    doc: 'application/msword',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ppt: 'application/vnd.ms-powerpoint',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '7z': 'application/x-7z-compressed'
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
    let size = bytes;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    return `${size.toFixed(2)} ${units[unitIndex]}`;
}

// 新增: 生成密码输入页面的函数
function generatePasswordPromptPage(isError) {
    return `<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>需要密码</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f0f2f5; margin: 0; }
            .container { background: white; padding: 2rem 3rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; }
            h2 { margin-top: 0; color: #333; }
            .form-group { margin: 1.5rem 0; }
            input[type="password"] { width: 100%; padding: 0.8rem; border: 1px solid #ccc; border-radius: 4px; font-size: 1rem; box-sizing: border-box; }
            button { width: 100%; padding: 0.8rem; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; transition: background-color 0.2s; }
            button:hover { background: #0056b3; }
            .error { color: #dc3545; margin-top: 1rem; font-size: 0.9rem; }
        </style>
    </head>
    <body>
        <div class="container">
            <form method="POST">
                <h2>请输入密码访问文件</h2>
                <div class="form-group">
                    <input type="password" name="password" placeholder="访问密码" required autofocus>
                </div>
                <button type="submit">确认</button>
                ${isError ? '<p class="error">密码错误，请重试。</p>' : ''}
            </form>
        </div>
    </body>
    </html>`;
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
        background: #f5f5f5;
        font-family: Arial, sans-serif;
        background-size: cover;
        background-position: center;
        transition: background-image 1s ease-in-out;
      }
      .login-container {
        background: rgba(255, 255, 255, 0.8);
        backdrop-filter: blur(10px);
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
      async function setBingBackground() {
        try {
          const response = await fetch('/bing');
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
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        background: #f5f5f5;
        margin: 0;
        background-size: cover;
        background-position: center;
        transition: background-image 1s ease-in-out;
      }
      .container {
        max-width: 800px;
        width: 100%;
        background: rgba(255, 255, 255, 0.8);
        backdrop-filter: blur(10px);
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
      .password-area {
        margin-top: 15px;
        text-align: center;
      }
      .password-area input {
        padding: 8px;
        border-radius: 4px;
        border: 1px solid #ddd;
        width: 50%;
        background: rgba(255, 255, 255, 0.5);
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
      <!-- 新增: 密码输入框 -->
      <div class="password-area">
        <input type="password" id="filePassword" placeholder="可选：为文件设置访问密码">
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
      async function setBingBackground() {
        try {
          const response = await fetch('/bing');
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
            await handleFiles({ target: { files: [file] } });
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
        // 新增: 将密码添加到表单数据中
        const password = document.getElementById('filePassword').value;
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
        let size = bytes;
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
          size /= 1024;
          unitIndex++;
        }
        return \`\${size.toFixed(2)} \${units[unitIndex]}\`;
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
function generateAdminPage(fileCards, modals, stats) {
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
        background: #f5f5f5;
        background-size: cover;
        background-position: center;
        transition: background-image 1s ease-in-out;
      }
      .container {
        max-width: 1200px;
        margin: 0 auto;
      }
      .header {
        background: rgba(255, 255, 255, 0.8);
        backdrop-filter: blur(10px);
        padding: 20px 30px;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
      }
      .header-left {
        display: flex;
        align-items: center;
        gap: 20px;
      }
      h2 { margin: 0; }
      /* 新增: 文件统计信息样式 */
      #stats { 
        color: red; 
        font-weight: bold; 
        font-size: 1.1em;
      }
      .header-right {
        display: flex;
        align-items: center;
        gap: 15px;
      }
      .search {
        padding: 8px;
        border: 1px solid #ddd;
        border-radius: 4px;
        width: 250px;
        background: rgba(255, 255, 255, 0.5);
      }
      .backup {
        color: #007bff;
        text-decoration: none;
      }
      .backup:hover { text-decoration: underline; }
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
        transition: transform 0.2s, box-shadow 0.2s;
        display: flex;
        flex-direction: column;
      }
      .file-card.selected {
        transform: translateY(-5px);
        box-shadow: 0 8px 20px rgba(0, 123, 255, 0.3);
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
        flex-grow: 1;
      }
      .file-name { font-weight: bold; color: #333; margin-bottom: 4px; }
      .file-meta { font-size: 12px; color: #666; margin-bottom: 4px; }
      .file-password { font-size: 12px; color: #6c757d; cursor: pointer; margin-bottom: 4px; }
      .file-password:hover { color: #007bff; }
      .file-actions {
        padding: 10px;
        border-top: 1px solid #eee;
        display: flex;
        justify-content: flex-end;
        align-items: center;
        gap: 5px;
        font-size: 12px;
        flex-wrap: wrap;
      }
      .file-checkbox {
        position: absolute;
        left: 10px;
        top: 10px;
        z-index: 10;
        transform: scale(1.2);
      }
      .btn {
        padding: 5px 10px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        background: #007bff; 
        color: white;
      }
      .btn-delete { background: #dc3545; }
      .btn-edit { background: #ffc107; color: black; }
      .btn-down { background: #28a745; text-decoration: none; }
      .btn-close { background: #6c757d; }
      /* 新增: 弹窗样式 */
      .modal-overlay {
        display: none; position: fixed; top: 0; left: 0;
        width: 100%; height: 100%;
        background: rgba(0, 0, 0, 0.5);
        justify-content: center; align-items: center; z-index: 1000;
      }
      .modal-content {
        background: white; padding: 20px; border-radius: 10px;
        text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        width: 90%; max-width: 400px;
      }
      #qrcode { margin: 15px 0; }
      #qrLinkContainer { margin-top: 15px; text-align: center; }
      #qrLinkContainer a { word-break: break-all; color: #007bff; }
      .modal-buttons { display: flex; gap: 10px; justify-content: center; margin-top: 20px; }
      .modal-content .form-group { text-align: left; margin-bottom: 15px; }
      .modal-content .form-group label { display: block; margin-bottom: 5px; }
      .modal-content .form-group input { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <div class="header-left">
          <h2>文件管理</h2>
          <div id="stats">共 ${stats.count} 个文件，总大小 ${stats.size}</div>
        </div>
        <div class="header-right">
          <button id="deleteSelectedBtn" class="btn btn-delete" style="display: none;">删除选中</button>
          <input type="checkbox" id="selectAllCheckbox" title="全选">
          <a href="/upload" class="backup">返回上传</a>
          <input type="text" class="search" placeholder="搜索文件..." id="searchInput">
        </div>
      </div>
      <div class="grid" id="fileGrid">
        ${fileCards}
      </div>
      ${modals}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      async function setBingBackground() {
        try {
          const response = await fetch('/bing');
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

      const searchInput = document.getElementById('searchInput');
      const fileGrid = document.getElementById('fileGrid');
      
      searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        document.querySelectorAll('.file-card').forEach(card => {
          const fileName = card.querySelector('.file-name').textContent.toLowerCase();
          card.style.display = fileName.includes(searchTerm) ? '' : 'none';
        });
      });

      // 分享二维码功能
      let currentShareUrl = '';
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

      function closeAllModals() {
        document.querySelectorAll('.modal-overlay').forEach(modal => modal.style.display = 'none');
      }      
      window.onclick = (event) => {
        if (event.target.classList.contains('modal-overlay')) {
            closeAllModals();
        }
      }

      // 单个文件删除功能
      async function deleteFile(url) {
        if (!confirm('确定要删除这个文件吗？')) return;
        await performDelete([url]);
      }

      // --- 全选和批量删除逻辑 ---
      const selectAllCheckbox = document.getElementById('selectAllCheckbox');
      const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
      const fileCheckboxes = document.querySelectorAll('.file-checkbox');

      function updateSelectionState() {
        const selectedCheckboxes = document.querySelectorAll('.file-checkbox:checked');
        const allCheckboxes = document.querySelectorAll('.file-checkbox');
        
        deleteSelectedBtn.style.display = selectedCheckboxes.length > 0 ? 'inline-block' : 'none';
        if (selectedCheckboxes.length > 0) {
            deleteSelectedBtn.textContent = \`删除选中 (\${selectedCheckboxes.length})\`;
        }

        if (allCheckboxes.length > 0) {
            selectAllCheckbox.checked = selectedCheckboxes.length === allCheckboxes.length;
            selectAllCheckbox.indeterminate = selectedCheckboxes.length > 0 && selectedCheckboxes.length < allCheckboxes.length;
        }

        fileCheckboxes.forEach(cb => {
            cb.closest('.file-card').classList.toggle('selected', cb.checked);
        });
      }

      selectAllCheckbox.addEventListener('change', (e) => {
        fileCheckboxes.forEach(checkbox => checkbox.checked = e.target.checked);
        updateSelectionState();
      });

      fileCheckboxes.forEach(checkbox => checkbox.addEventListener('change', updateSelectionState));

      deleteSelectedBtn.addEventListener('click', async () => {
        const selectedUrls = Array.from(document.querySelectorAll('.file-checkbox:checked'))
          .map(cb => cb.closest('.file-card').dataset.url);
        
        if (selectedUrls.length === 0 || !confirm(\`确定要删除选中的 \${selectedUrls.length} 个文件吗？\n此操作不可恢复！\`)) return;
        
        await performDelete(selectedUrls);
      });
      
      async function performDelete(urls) {
        try {
          const response = await fetch('/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls })
          });

          if (!response.ok) throw new Error((await response.json()).error || '删除请求失败');
          
          const resultData = await response.json();
          let successCount = 0;
          resultData.results.forEach(res => {
              if(res.success) {
                  document.querySelector(\`[data-url="\${res.url}"]\`)?.remove();
                  successCount++;
              } else {
                  console.error(\`删除 \${res.url} 失败: \`, res.error);
              }
          });
          alert(\`删除操作完成: \${successCount}个成功, \${urls.length - successCount}个失败。\`);

        } catch (error) {
          alert('删除失败: ' + error.message);
        } finally {
            updateSelectionState();
        }
      }
      
      // --- 新增: 编辑和密码复制功能 ---
      function copyPassword(password, element) {
        navigator.clipboard.writeText(password).then(() => {
            const originalText = element.innerHTML;
            element.innerHTML = '密码已复制!';
            setTimeout(() => { element.innerHTML = originalText; }, 2000);
        });
      }

      function showEditModal(url) {
        const card = document.querySelector(\`[data-url="\${url}"]\`);
        document.getElementById('editFileUrl').value = url;
        document.getElementById('editFileName').value = card.dataset.filename;
        document.getElementById('editFilePassword').value = card.dataset.password;
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

            if (!response.ok) throw new Error((await response.json()).error || '更新失败');
            
            const result = await response.json();
            if (result.success) {
                alert('更新成功!');
                window.location.reload(); // 刷新页面以查看更改
            } else {
                alert('更新失败: ' + (result.error || '未知错误'));
            }
        } catch (error) {
            alert('操作失败: ' + error.message);
        }
      }

      updateSelectionState();
    </script>
  </body>
  </html>`;
}
