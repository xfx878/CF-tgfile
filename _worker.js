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
      custom_name TEXT,
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
      '/update': () => handleUpdateRequest(request, config),
      '/search': () => handleSearchRequest(request, config),
      '/bing': () => handleBingImagesRequest(request, config)
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
      INSERT INTO files (url, fileId, message_id, created_at, file_name, custom_name, file_size, mime_type, password) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      url,
      fileId,
      messageId,
      timestamp,
      file.name,
      file.name, // 默认 custom_name 和 file_name 一样
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
    let statusCode = 500;
    if (error.message.includes(`文件超过${config.maxSizeMB}MB限制`)) {
      statusCode = 400;
    } else if (error.message.includes('Telegram参数配置错误')) {
      statusCode = 502;
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

  const { results } = await config.database.prepare(
    `SELECT url, fileId, message_id, created_at, file_name, custom_name, file_size, mime_type, password
    FROM files
    ORDER BY created_at DESC`
  ).all();

  const fileList = results || [];
  let totalSize = 0;
  const fileCards = fileList.map(file => {
    totalSize += file.file_size || 0;
    const displayName = file.custom_name || file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const passwordDisplay = file.password ? `
        <div class="password-info" title="点击复制密码" onclick="copyPassword(event, '${file.password}')">
            密码: ${file.password.substring(0, 3)}...
        </div>` : '<div>无密码</div>';

    return `
      <div class="file-card" data-url="${file.url}">
        <input type="checkbox" class="file-checkbox">
        <div class="file-preview">
          ${getPreviewHtml(file.url)}
        </div>
        <div class="file-info">
          <div class="file-name" title="${displayName}">${displayName}</div>
          <div>${fileSize}</div>
          ${passwordDisplay}
          <div>${createdAt}</div>
        </div>
        <div class="file-actions">
          <button class="btn btn-edit" onclick="openEditModal('${file.url}', '${displayName}', '${file.password || ''}')">编辑</button>
          <button class="btn btn-copy" onclick="showShareOptions('${file.url}')">分享</button>
          <a class="btn btn-down" href="${file.url}" download="${displayName}">下载</a>
        </div>
      </div>
    `;
  }).join('');
  
  const totalFiles = fileList.length;
  const stats = `<div class="stats">总文件数: ${totalFiles} | 总大小: ${formatSize(totalSize)}</div>`;

  const modals = generateModals();
  const html = generateAdminPage(stats, fileCards, modals);
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

// 处理文件搜索
async function handleSearchRequest(request, config) {
    // This function remains the same as in the original code.
    // ...
}

// 支持预览的文件类型
function getPreviewHtml(url) {
    // This function remains the same as in the original code.
    // ...
}

// 获取文件并缓存
async function handleFileRequest(request, config) {
  const url = new URL(request.url);
  const cache = caches.default;
  const cacheKey = new Request(url.href);

  // 检查是否有密码验证的cookie
  const cookies = request.headers.get('Cookie') || '';
  const fileAuthCookie = cookies.split('; ').find(row => row.startsWith('file_auth='));
  
  try {
    const file = await config.database.prepare(
      `SELECT fileId, message_id, file_name, mime_type, password
      FROM files WHERE url = ?`
    ).bind(url.href).first();

    if (!file) {
      return new Response('文件不存在', { status: 404 });
    }

    // 如果文件有密码
    if (file.password) {
      if (request.method === 'POST') {
        const formData = await request.formData();
        const submittedPassword = formData.get('password');
        if (submittedPassword === file.password) {
          const response = new Response(null, { status: 302 });
          const cookie = `file_auth=${btoa(url.href + file.password)}; Path=/; Max-Age=3600; HttpOnly; Secure`;
          response.headers.set('Set-Cookie', cookie);
          response.headers.set('Location', url.href);
          return response;
        } else {
          return new Response(generatePasswordPage(url.href, '密码错误'), {
            status: 401,
            headers: { 'Content-Type': 'text/html;charset=UTF-8' }
          });
        }
      }

      if (!fileAuthCookie || atob(fileAuthCookie.split('=')[1]) !== (url.href + file.password)) {
        return new Response(generatePasswordPage(url.href), {
          status: 401,
          headers: { 'Content-Type': 'text/html;charset=UTF-8' }
        });
      }
    }

    // 缓存逻辑
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) return cachedResponse;

    // 从Telegram获取文件
    const tgResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/getFile?file_id=${file.fileId}`);
    if (!tgResponse.ok) throw new Error('获取文件信息失败');
    
    const tgData = await tgResponse.json();
    const filePath = tgData.result?.file_path;
    if (!filePath) throw new Error('文件路径无效');

    const fileUrl = `https://api.telegram.org/file/bot${config.tgBotToken}/${filePath}`;
    const fileResponse = await fetch(fileUrl);
    if (!fileResponse.ok) throw new Error('下载文件失败');

    const response = new Response(fileResponse.body, {
      headers: {
        'Content-Type': file.mime_type || getContentType(url.pathname.split('.').pop()),
        'Cache-Control': 'public, max-age=31536000',
        'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(file.file_name || '')}`
      }
    });

    await cache.put(cacheKey, response.clone());
    return response;

  } catch (error) {
    console.error(`[File Request Error] ${error.message} for ${url.href}`);
    return new Response('服务器内部错误', { status: 500 });
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
      return new Response(JSON.stringify({ error: '无效的URL列表' }), { status: 400 });
    }

    const results = [];
    for (const url of urls) {
      const file = await config.database.prepare(
        'SELECT message_id FROM files WHERE url = ?'
      ).bind(url).first();

      if (file) {
        try {
          const deleteResponse = await fetch(
            `https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`
          );
          if (!deleteResponse.ok) {
             console.error(`TG删除失败 for ${url}: ${await deleteResponse.text()}`);
          }
        } catch (e) {
            console.error(`TG删除网络错误 for ${url}: ${e.message}`);
        }
        await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
        results.push({ url, success: true });
      } else {
        results.push({ url, success: false, error: '文件未找到' });
      }
    }
    
    // 清除缓存
    const cache = caches.default;
    for (const url of urls) {
        await cache.delete(new Request(url));
    }

    return new Response(JSON.stringify({ success: true, results }), {
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
}

// 处理文件信息更新
async function handleUpdateRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
    }
    try {
        const { url, custom_name, password } = await request.json();
        if (!url) {
            return new Response(JSON.stringify({ error: 'URL是必须的' }), { status: 400 });
        }

        await config.database.prepare(
            'UPDATE files SET custom_name = ?, password = ? WHERE url = ?'
        ).bind(custom_name, password, url).run();

        return new Response(JSON.stringify({ success: true, message: '更新成功' }), {
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        console.error(`[Update Error] ${error.message}`);
        return new Response(JSON.stringify({ error: error.message }), { status: 500 });
    }
}

// 支持上传的文件类型
function getContentType(ext) {
    // This function remains the same as in the original code.
    // ...
}

async function handleBingImagesRequest(request, config) {
    // This function remains the same as in the original code.
    // ...
}

// 文件大小计算函数
function formatSize(bytes) {
    // This function remains the same as in the original code.
    // ...
}

// 登录页面生成函数 /login
function generateLoginPage() {
    // This function remains the same as in the original code.
    // ...
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
        background: #f5f5f5;
        margin: 0;
      }
      .container {
        max-width: 800px;
        width: 100%;
        background: rgba(255, 255, 255, 0.7);
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
      .password-input {
        width: calc(100% - 20px);
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
      <input type="text" id="passwordInput" class="password-input" placeholder="访问密码 (可选)">
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
      // 背景图函数
      async function setBingBackground() {
        try {
          const response = await fetch('/bing');
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
            document.body.style.backgroundSize = 'cover';
            document.body.style.backgroundPosition = 'center';
          }
        } catch (error) {
          console.error('获取背景图失败:', error);
        }
      }
      setBingBackground(); 
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

      function preventDefaults(e) { e.preventDefault(); e.stopPropagation(); }
      function highlight(e) { uploadArea.classList.add('dragover'); }
      function unhighlight(e) { uploadArea.classList.remove('dragover'); }

      ['dragenter', 'dragover'].forEach(eventName => uploadArea.addEventListener(eventName, highlight, false));
      ['dragleave', 'drop'].forEach(eventName => uploadArea.addEventListener(eventName, unhighlight, false));

      uploadArea.addEventListener('drop', handleDrop, false);
      uploadArea.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', () => handleFiles(fileInput.files));

      function handleDrop(e) {
        handleFiles(e.dataTransfer.files);
      }

      document.addEventListener('paste', (e) => {
        handleFiles((e.clipboardData || e.originalEvent.clipboardData).files);
      });

      async function handleFiles(files) {
        const response = await fetch('/config');
        const config = await response.json();
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
            if (xhr.status >= 200 && xhr.status < 300 && data.status === 1) {
              progressText.textContent = data.msg;
              uploadedUrls.push(data.url);
              updateUrlArea();
              preview.classList.add('success');
            } else {
              const errorMsg = data.msg || data.error || '未知错误';
              progressText.textContent = '✘ ' + errorMsg;
              preview.classList.add('error');
            }
          } catch (e) {
            progressText.textContent = '✘ 响应解析失败';
            preview.classList.add('error');
          }
        });
        
        xhr.addEventListener('error', () => {
            progressText.textContent = '✘ 上传错误';
            preview.classList.add('error');
        });

        const formData = new FormData();
        formData.append('file', file);
        const password = passwordInput.value;
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
        const units = ['B', 'KB', 'MB', 'GB'];
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
        navigator.clipboard.writeText(text).then(() => alert('已复制到剪贴板'));
      }
    </script>
  </body>
  </html>`;
}

// 生成文件管理页面 /admin
function generateAdminPage(stats, fileCards, modals) {
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
        transition: background-image 1s ease-in-out;
      }
      .container { max-width: 1200px; margin: 0 auto; }
      .header {
        background: rgba(255, 255, 255, 0.8);
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        margin-bottom: 20px;
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        align-items: center;
        gap: 15px;
      }
      h2 { margin: 0; }
      .stats {
        font-size: 1.2em;
        font-weight: bold;
        color: red;
      }
      .search-container { display: flex; align-items: center; gap: 10px; }
      .search { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 250px; }
      .actions-container { display: flex; align-items: center; gap: 10px; }
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
        background: #eee;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .file-preview img, .file-preview video { max-width: 100%; max-height: 100%; object-fit: contain; }
      .file-info { padding: 10px; font-size: 14px; flex-grow: 1; }
      .file-info > div { margin-bottom: 5px; word-break: break-all; }
      .file-name { font-weight: bold; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .password-info { cursor: pointer; color: #0056b3; }
      .file-actions { padding: 10px; border-top: 1px solid #eee; display: flex; justify-content: space-around; }
      .file-checkbox { position: absolute; left: 10px; top: 10px; z-index: 10; transform: scale(1.2); }
      .btn { padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; color: white; }
      .btn-delete-selected { background: #dc3545; }
      .btn-edit { background: #ffc107; }
      .btn-copy { background: #17a2b8; }
      .btn-down { background: #007bff; text-decoration: none; display: inline-block; }
      .modal {
        display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%;
        overflow: auto; background-color: rgba(0,0,0,0.5); justify-content: center; align-items: center;
      }
      .modal-content {
        background-color: #fefefe; margin: auto; padding: 20px; border: 1px solid #888;
        width: 80%; max-width: 500px; border-radius: 8px;
      }
      .modal-content input { width: calc(100% - 22px); padding: 10px; margin: 10px 0; }
      .modal-buttons { display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px; }
      .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h2>文件管理</h2>
        ${stats}
        <div class="search-container">
          <input type="text" class="search" placeholder="搜索文件..." id="searchInput">
        </div>
        <div class="actions-container">
          <label><input type="checkbox" id="selectAllCheckbox"> 全选</label>
          <button class="btn btn-delete-selected" id="deleteSelectedBtn">删除选中</button>
          <a href="/upload" class="btn btn-down">返回上传</a>
        </div>
      </div>
      <div class="grid" id="fileGrid">
        ${fileCards}
      </div>
      ${modals}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      // 背景图函数
      async function setBingBackground() {
        try {
          const response = await fetch('/bing');
          const data = await response.json();
          if (data.status && data.data && data.data.length > 0) {
            const randomIndex = Math.floor(Math.random() * data.data.length);
            document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`;
            document.body.style.backgroundSize = 'cover';
            document.body.style.backgroundPosition = 'center';
            document.body.style.backgroundAttachment = 'fixed';
          }
        } catch (error) {
          console.error('获取背景图失败:', error);
        }
      }
      setBingBackground();
      setInterval(setBingBackground, 3600000);

      const searchInput = document.getElementById('searchInput');
      const fileGrid = document.getElementById('fileGrid');
      const selectAllCheckbox = document.getElementById('selectAllCheckbox');
      const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');

      // 搜索功能
      searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        document.querySelectorAll('.file-card').forEach(card => {
          const fileName = card.querySelector('.file-name').textContent.toLowerCase();
          card.style.display = fileName.includes(searchTerm) ? 'flex' : 'none';
        });
      });

      // 全选/取消全选
      selectAllCheckbox.addEventListener('change', (e) => {
        document.querySelectorAll('.file-checkbox').forEach(checkbox => {
          checkbox.checked = e.target.checked;
        });
      });

      // 删除选中
      deleteSelectedBtn.addEventListener('click', async () => {
        const selectedCards = document.querySelectorAll('.file-checkbox:checked');
        if (selectedCards.length === 0) {
          alert('请先选择要删除的文件');
          return;
        }
        if (!confirm(\`确定要删除选中的 \${selectedCards.length} 个文件吗？\`)) return;

        const urlsToDelete = Array.from(selectedCards).map(cb => cb.closest('.file-card').dataset.url);
        
        try {
          const response = await fetch('/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls: urlsToDelete })
          });
          const result = await response.json();
          if (result.success) {
            alert('选中的文件已删除');
            selectedCards.forEach(cb => cb.closest('.file-card').remove());
          } else {
            throw new Error(result.error || '删除失败');
          }
        } catch (error) {
          alert('删除失败: ' + error.message);
        }
      });
      
      // 复制密码
      function copyPassword(event, password) {
          event.stopPropagation();
          navigator.clipboard.writeText(password).then(() => {
              alert('密码已复制到剪贴板');
          });
      }

      // 模态框通用逻辑
      function closeModal(modalId) {
        document.getElementById(modalId).style.display = 'none';
      }
      window.onclick = function(event) {
        if (event.target.classList.contains('modal')) {
          event.target.style.display = 'none';
        }
      }

      // 编辑模态框
      function openEditModal(url, name, password) {
        const modal = document.getElementById('editModal');
        document.getElementById('editUrl').value = url;
        document.getElementById('editName').value = name;
        document.getElementById('editPassword').value = password;
        modal.style.display = 'flex';
      }

      document.getElementById('editForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        const url = document.getElementById('editUrl').value;
        const custom_name = document.getElementById('editName').value;
        const password = document.getElementById('editPassword').value;

        try {
            const response = await fetch('/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, custom_name, password })
            });
            const result = await response.json();
            if (result.success) {
                alert('更新成功');
                closeModal('editModal');
                location.reload(); // 简单刷新页面
            } else {
                throw new Error(result.error || '更新失败');
            }
        } catch (error) {
            alert('更新失败: ' + error.message);
        }
      });

      // 分享模态框
      let currentShareUrl = '';
      function showShareOptions(url) {
        currentShareUrl = url;
        const modal = document.getElementById('shareModal');
        const qrcodeDiv = document.getElementById('qrcode');
        qrcodeDiv.innerHTML = '';
        new QRCode(qrcodeDiv, { text: url, width: 200, height: 200 });
        modal.style.display = 'flex';
      }

      function copyShareLink(format) {
          let text = '';
          const url = currentShareUrl;
          switch (format) {
              case 'url': text = url; break;
              case 'markdown': text = \`![](\${url})\`; break;
              case 'html': text = \`<img src="\${url}">\`; break;
          }
          navigator.clipboard.writeText(text).then(() => alert('已复制到剪贴板'));
      }
    </script>
  </body>
  </html>`;
}

// 生成模态框HTML
function generateModals() {
    return `
    <!-- 编辑模态框 -->
    <div id="editModal" class="modal">
      <div class="modal-content">
        <span class="close" onclick="closeModal('editModal')">&times;</span>
        <h2>编辑文件信息</h2>
        <form id="editForm">
          <input type="hidden" id="editUrl">
          <label for="editName">文件名:</label>
          <input type="text" id="editName" required>
          <label for="editPassword">密码 (留空则无密码):</label>
          <input type="text" id="editPassword">
          <div class="modal-buttons">
            <button type="button" class="btn" onclick="closeModal('editModal')" style="background-color: #6c757d;">取消</button>
            <button type="submit" class="btn" style="background-color: #007bff;">保存</button>
          </div>
        </form>
      </div>
    </div>

    <!-- 分享模态框 -->
    <div id="shareModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('shareModal')">&times;</span>
            <h2>分享文件</h2>
            <div id="qrcode" style="display:flex; justify-content: center; margin-bottom: 15px;"></div>
            <div class="modal-buttons" style="justify-content: center;">
                <button class="btn" onclick="copyShareLink('url')" style="background-color: #007bff;">复制链接</button>
                <button class="btn" onclick="copyShareLink('markdown')" style="background-color: #17a2b8;">Markdown</button>
                <button class="btn" onclick="copyShareLink('html')" style="background-color: #28a745;">HTML</button>
            </div>
        </div>
    </div>
    `;
}

// 生成密码输入页面
function generatePasswordPage(url, error = '') {
    return `<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>需要密码</title>
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; font-family: sans-serif; }
            .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); text-align: center; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            .error { color: red; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>此文件受密码保护</h2>
            <form method="POST" action="${url}">
                <input type="password" name="password" placeholder="请输入密码" required>
                <button type="submit">提交</button>
            </form>
            ${error ? `<div class="error">${error}</div>` : ''}
        </div>
    </body>
    </html>`;
}
