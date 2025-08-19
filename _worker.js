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
      '/update': () => handleUpdateRequest(request, config), // 新增：处理文件更新
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
      const tokenData = JSON.parse(atob(authToken[1]));
      if (Date.now() > tokenData.expiration) {
        console.log("Token已过期");
        return false;
      }
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
    if (!authenticate(request, config)) {
      return handleLoginRequest(request, config);
    }
    return handleUploadRequest(request, config);
  }
  return handleUploadRequest(request, config);
}

// 处理登录
async function handleLoginRequest(request, config) {
  if (request.method === 'POST') {
    const { username, password } = await request.json();
    if (username === config.username && password === config.password) {
      const expirationDate = new Date();
      expirationDate.setDate(expirationDate.getDate() + config.cookie);
      const tokenData = JSON.stringify({
        username: config.username,
        expiration: expirationDate.getTime()
      });
      const token = btoa(tokenData);
      const cookie = `auth_token=${token}; Path=/; HttpOnly; Secure; Expires=${expirationDate.toUTCString()}`;
      return new Response("登录成功", {
        status: 200,
        headers: { "Set-Cookie": cookie, "Content-Type": "text/plain" }
      });
    }
    return new Response("认证失败", { status: 401 });
  }
  return new Response(generateLoginPage(), {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

// 处理文件上传
async function handleUploadRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return Response.redirect(`${new URL(request.url).origin}/`, 302);
  }
  if (request.method === 'GET') {
    return new Response(generateUploadPage(), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' }
    });
  }

  try {
    const formData = await request.formData();
    const file = formData.get('file');
    const password = formData.get('password') || null; // 获取密码

    if (!file) throw new Error('未找到文件');
    if (file.size > config.maxSizeMB * 1024 * 1024) throw new Error(`文件超过${config.maxSizeMB}MB限制`);
    
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    const mimeType = getContentType(ext);
    const [mainType] = mimeType.split('/');
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
    const tgResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/${method}`, { method: 'POST', body: tgFormData });
    if (!tgResponse.ok) throw new Error('Telegram参数配置错误');

    const tgData = await tgResponse.json();
    const result = tgData.result;
    const messageId = result?.message_id;
    const fileId = result?.document?.file_id || result?.video?.file_id || result?.audio?.file_id || (result?.photo && result.photo[result.photo.length - 1]?.file_id);
    if (!fileId || !messageId) throw new Error('未获取到文件或消息ID');

    const time = Date.now();
    const timestamp = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();
    const url = `https://${config.domain}/${time}.${ext}`;
    
    await config.database.prepare(`
      INSERT INTO files (url, fileId, message_id, created_at, file_name, file_size, mime_type, password) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(url, fileId, messageId, timestamp, file.name, file.size, file.type || getContentType(ext), password).run();

    return new Response(JSON.stringify({ status: 1, msg: "✔ 上传成功", url }), { headers: { 'Content-Type': 'application/json' } });
  } catch (error) {
    console.error(`[Upload Error] ${error.message}`);
    let statusCode = 500;
    if (error.message.includes(`文件超过${config.maxSizeMB}MB限制`)) statusCode = 400;
    else if (error.message.includes('Telegram参数配置错误')) statusCode = 502;
    return new Response(JSON.stringify({ status: 0, msg: "✘ 上传失败", error: error.message }), { status: statusCode, headers: { 'Content-Type': 'application/json' } });
  }
}

// 处理文件管理和预览
async function handleAdminRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return Response.redirect(`${new URL(request.url).origin}/`, 302);
  }

  const files = await config.database.prepare(
    `SELECT url, file_name, file_size, created_at, password FROM files ORDER BY created_at DESC`
  ).all();

  const fileList = files.results || [];
  const totalSize = fileList.reduce((sum, file) => sum + (file.file_size || 0), 0);
  const stats = { count: fileList.length, size: formatSize(totalSize) };

  const fileCards = fileList.map(file => {
    const fileName = file.file_name || 'N/A';
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const passwordDisplay = file.password ? `<div class="file-password" title="点击复制密码" onclick="copyPassword('${file.password}')">密码: ${file.password}</div>` : '<div>无密码</div>';
    
    return `
      <div class="file-card" data-url="${file.url}" data-name="${fileName}" data-password="${file.password || ''}">
        <input type="checkbox" class="file-checkbox">
        <div class="file-preview">${getPreviewHtml(file.url)}</div>
        <div class="file-info">
          <div class="file-name">${fileName}</div>
          <div>${fileSize}</div>
          <div>${createdAt}</div>
          ${passwordDisplay}
        </div>
        <div class="file-actions">
          <button class="btn btn-copy" onclick="showQRCode('${file.url}')">分享</button>
          <button class="btn btn-edit" onclick="showEditModal('${file.url}', '${fileName}', '${file.password || ''}')">编辑</button>
          <a class="btn btn-down" href="${file.url}" download="${fileName}">下载</a>
          <button class="btn btn-delete" onclick="deleteFile('${file.url}')">删除</button>
        </div>
      </div>
    `;
  }).join('');

  const modalHtml = `
    <div id="qrModal" class="modal">
      <div class="modal-content">
        <div id="qrcode"></div>
        <div class="url-container">
          <a id="qrUrlLink" href="#" target="_blank"></a>
          <button id="qrUrlCopyBtn">复制</button>
        </div>
        <button class="modal-close" onclick="closeModal('qrModal')">关闭</button>
      </div>
    </div>
    <div id="editModal" class="modal">
      <div class="modal-content">
        <h3>编辑文件信息</h3>
        <input type="hidden" id="editFileUrl">
        <div class="form-group"><label>文件名:</label><input type="text" id="editFileName"></div>
        <div class="form-group"><label>密码 (留空则无密码):</label><input type="text" id="editFilePassword"></div>
        <div class="modal-buttons">
          <button class="btn-save" onclick="handleUpdateFile()">保存</button>
          <button class="modal-close" onclick="closeModal('editModal')">取消</button>
        </div>
      </div>
    </div>
  `;

  const html = generateAdminPage(fileCards, modalHtml, stats);
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

// 获取文件并处理密码
async function handleFileRequest(request, config) {
  const url = new URL(request.url);
  const cache = caches.default;
  const cacheKey = new Request(url.href, { headers: request.headers });

  // 检查会话cookie
  const cookies = request.headers.get('Cookie') || '';
  const sessionToken = cookies.match(/session_token=([^;]+)/);
  const hasValidSession = sessionToken && sessionToken[1] === btoa(url.href);

  if (!hasValidSession) {
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) return cachedResponse;
  }

  const file = await config.database.prepare(
    `SELECT fileId, file_name, mime_type, password FROM files WHERE url = ?`
  ).bind(url.href).first();

  if (!file) {
    return new Response('文件不存在', { status: 404 });
  }

  // 密码保护逻辑
  if (file.password && !hasValidSession) {
    if (request.method === 'POST') {
      const formData = await request.formData();
      if (formData.get('password') === file.password) {
        const response = new Response(null, { status: 302, headers: { 'Location': url.href } });
        const cookie = `session_token=${btoa(url.href)}; Path=${url.pathname}; HttpOnly; Secure; Max-Age=3600`; // 1小时有效
        response.headers.append('Set-Cookie', cookie);
        return response;
      } else {
        return new Response(generatePasswordPromptPage(url.href, true), { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
      }
    }
    return new Response(generatePasswordPromptPage(url.href), { status: 200, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  // 获取文件并提供下载
  try {
    const tgResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/getFile?file_id=${file.fileId}`);
    if (!tgResponse.ok) throw new Error('获取TG文件信息失败');
    const tgData = await tgResponse.json();
    const filePath = tgData.result?.file_path;
    if (!filePath) throw new Error('无效的文件路径');

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

    if (!hasValidSession) {
      await cache.put(cacheKey, response.clone());
    }
    return response;
  } catch (error) {
    console.error(`[File Request Error] ${error.message}`);
    return new Response('服务器内部错误', { status: 500 });
  }
}

// 新增：处理文件信息更新
async function handleUpdateRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ error: '未授权' }), { status: 401 });
  }
  if (request.method !== 'POST') return new Response('无效请求', { status: 405 });

  try {
    const { url, fileName, password } = await request.json();
    if (!url || !fileName) {
      return new Response(JSON.stringify({ success: false, message: '缺少必要参数' }), { status: 400 });
    }

    await config.database.prepare(
      'UPDATE files SET file_name = ?, password = ? WHERE url = ?'
    ).bind(fileName, password || null, url).run();

    return new Response(JSON.stringify({ success: true, message: '更新成功' }), { headers: { 'Content-Type': 'application/json' } });
  } catch (error) {
    console.error(`[Update Error] ${error.message}`);
    return new Response(JSON.stringify({ success: false, message: '服务器错误' }), { status: 500 });
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
      const file = await config.database.prepare('SELECT message_id FROM files WHERE url = ?').bind(url).first();
      if (!file) {
        results.push({ url, success: false, error: '文件不存在' });
        continue;
      }
      
      try {
        const deleteResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`);
        if (!deleteResponse.ok) {
            const errorData = await deleteResponse.json();
            throw new Error(errorData.description || 'Telegram API 错误');
        }
      } catch (tgError) {
          console.warn(`删除TG消息失败 for ${url}: ${tgError.message}. 继续删除数据库记录.`);
      }

      await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
      results.push({ url, success: true, message: '文件删除成功' });
    }
    
    return new Response(JSON.stringify({ results }), { headers: { 'Content-Type': 'application/json' } });
  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
}

// 其他辅助函数...
function getPreviewHtml(url) {
  const ext = (url.split('.').pop() || '').toLowerCase();
  const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'icon'].includes(ext);
  const isVideo = ['mp4', 'webm', 'mov', 'avi'].includes(ext);
  const isAudio = ['mp3', 'wav', 'ogg', 'flac'].includes(ext);

  if (isImage) return `<img src="${url}" alt="预览" loading="lazy">`;
  if (isVideo) return `<video src="${url}" controls></video>`;
  if (isAudio) return `<audio src="${url}" controls></audio>`;
  return `<div style="font-size: 48px">📄</div>`;
}

function getContentType(ext) {
  const types = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    webp: 'image/webp', svg: 'image/svg+xml', icon: 'image/x-icon',
    mp4: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime', avi: 'video/x-msvideo',
    mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg', flac: 'audio/flac',
    pdf: 'application/pdf', txt: 'text/plain', md: 'text/markdown',
    zip: 'application/zip', rar: 'application/x-rar-compressed', '7z': 'application/x-7z-compressed',
    json: 'application/json', xml: 'application/xml',
    doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  };
  return types[ext] || 'application/octet-stream';
}

async function handleBingImagesRequest() {
  const cacheKey = 'https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=5';
  try {
    const res = await fetch(cacheKey);
    if (!res.ok) throw new Error(`Bing API 请求失败: ${res.status}`);
    const bingData = await res.json();
    const images = bingData.images.map(image => ({ url: `https://cn.bing.com${image.url}` }));
    return new Response(JSON.stringify({ status: true, data: images }), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }});
  } catch (error) {
    console.error('请求 Bing API 失败:', error);
    return new Response(JSON.stringify({ status: false, message: error.message }), { status: 500 });
  }
}

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}

// 页面生成函数...
function generateLoginPage() {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>登录</title><style>body{display:flex;justify-content:center;align-items:center;height:100vh;background:#f5f5f5;font-family:Arial,sans-serif;background-size:cover;background-position:center;transition:background-image 1s ease-in-out}.login-container{background:rgba(255,255,255,.8);backdrop-filter:blur(10px);padding:20px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);width:100%;max-width:400px}h2{text-align:center;margin-bottom:2rem}.form-group{margin-bottom:1rem}input{width:100%;padding:.75rem;border:1px solid #ddd;border-radius:4px;font-size:1rem;box-sizing:border-box}button{width:100%;padding:.75rem;background:#007bff;color:#fff;border:none;border-radius:4px;font-size:1rem;cursor:pointer}button:hover{background:#0056b3}.error{color:#dc3545;margin-top:1rem;display:none}</style></head><body><div class="login-container"><h2>登录</h2><form id="loginForm"><div class="form-group"><input type="text" id="username" placeholder="用户名" required></div><div class="form-group"><input type="password" id="password" placeholder="密码" required></div><button type="submit">登录</button><div id="error" class="error">用户名或密码错误</div></form></div><script>async function setBingBackground(){try{const response=await fetch('/bing');const data=await response.json();if(data.status&&data.data.length>0){const randomIndex=Math.floor(Math.random()*data.data.length);document.body.style.backgroundImage=\`url(\${data.data[randomIndex].url})\`}}catch(error){console.error('获取背景图失败:',error)}};setBingBackground();setInterval(setBingBackground,3600000);document.getElementById('loginForm').addEventListener('submit',async e=>{e.preventDefault();const username=document.getElementById('username').value;const password=document.getElementById('password').value;try{const response=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});if(response.ok){window.location.href='/upload'}else{document.getElementById('error').style.display='block'}}catch(err){document.getElementById('error').style.display='block'}})</script></body></html>`;
}

function generateUploadPage() {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>文件上传</title><style>body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background-size:cover;background-position:center;transition:background-image 1s ease-in-out}.container{max-width:800px;width:100%;background:rgba(255,255,255,.8);backdrop-filter:blur(10px);padding:10px 40px 20px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);overflow-y:auto;max-height:90vh}.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}.upload-area{border:2px dashed #666;padding:40px;text-align:center;border-radius:8px;transition:all .3s}.upload-area.dragover{border-color:#007bff;background:#f8f9fa}#password-container{margin-top:15px;text-align:left}#password-container input{width:100%;padding:8px;border-radius:4px;border:1px solid #ddd;box-sizing:border-box}.preview-area{margin-top:20px}.preview-item{display:flex;align-items:center;padding:10px;border:1px solid #ddd;margin-bottom:10px;border-radius:4px}.preview-item img{max-width:100px;max-height:100px;margin-right:10px}.preview-item .info{flex-grow:1}.url-area textarea{width:100%;min-height:100px;padding:10px;border:1px solid #ddd;border-radius:4px}.button-group{margin-top:10px;display:flex;justify-content:space-between;align-items:center}.button-container button{margin-right:10px;padding:5px 10px;border:none;border-radius:4px;background:#007bff;color:#fff;cursor:pointer}.copyright{font-size:12px;color:#888}.progress-bar{height:20px;background:#eee;border-radius:10px;margin:8px 0;overflow:hidden;position:relative}.progress-track{height:100%;background:#007bff;transition:width .3s ease;width:0}.progress-text{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);color:#fff;font-size:12px;text-shadow:1px 1px 1px rgba(0,0,0,.5)}.success .progress-track{background:#28a745}.error .progress-track{background:#dc3545}</style></head><body><div class="container"><div class="header"><h1>文件上传</h1><a href="/admin" style="text-decoration:none;color:#007bff">进入管理页面</a></div><div class="upload-area" id="uploadArea"><p>点击选择 或 拖拽文件到此处</p><input type="file" id="fileInput" multiple style="display:none"></div><div id="password-container"><label for="filePassword">设置访问密码 (可选):</label><input type="text" id="filePassword" placeholder="留空则不设密码"></div><div class="preview-area" id="previewArea"></div><div class="url-area"><textarea id="urlArea" readonly placeholder="上传完成后的链接将显示在这里"></textarea><div class="button-group"><div class="button-container"><button onclick="copyUrls('url')">复制URL</button><button onclick="copyUrls('markdown')">复制Markdown</button><button onclick="copyUrls('html')">复制HTML</button></div><div class="copyright"><span>© 2025 by <a href="https://github.com/yutian81/CF-tgfile" target="_blank" style="text-decoration:none;color:inherit">yutian81</a></span></div></div></div></div><script>async function setBingBackground(){try{const r=await fetch('/bing'),a=await r.json();if(a.status&&a.data.length>0){const t=Math.floor(Math.random()*a.data.length);document.body.style.backgroundImage=\`url(\${a.data[t].url})\`}}catch(r){console.error('获取背景图失败:',r)}}setBingBackground();setInterval(setBingBackground,36e5);const uploadArea=document.getElementById('uploadArea'),fileInput=document.getElementById('fileInput'),previewArea=document.getElementById('previewArea'),urlArea=document.getElementById('urlArea');let uploadedUrls=[];['dragenter','dragover','dragleave','drop'].forEach(e=>{uploadArea.addEventListener(e,t,false);document.body.addEventListener(e,t,false)});function t(e){e.preventDefault();e.stopPropagation()};['dragenter','dragover'].forEach(e=>{uploadArea.addEventListener(e,()=>uploadArea.classList.add('dragover'),false)});['dragleave','drop'].forEach(e=>{uploadArea.addEventListener(e,()=>uploadArea.classList.remove('dragover'),false)});uploadArea.addEventListener('drop',e=>{const t=e.dataTransfer.files;handleFiles({target:{files:t}})},false);uploadArea.addEventListener('click',()=>fileInput.click());fileInput.addEventListener('change',handleFiles);document.addEventListener('paste',async e=>{for(let t of(e.clipboardData||e.originalEvent.clipboardData).items)if(t.kind==='file'){const n=t.getAsFile();await handleFiles({target:{files:[n]}})}});async function handleFiles(e){const t=await(await fetch('/config')).json();for(let n of Array.from(e.target.files)){if(n.size>t.maxSizeMB*1024*1024){alert(\`文件 \${n.name} 超过\${t.maxSizeMB}MB限制\`);continue}await uploadFile(n)}}async function uploadFile(e){const t=createPreview(e);previewArea.appendChild(t);const n=new XMLHttpRequest,r=t.querySelector('.progress-track'),a=t.querySelector('.progress-text');n.upload.addEventListener('progress',o=>{if(o.lengthComputable){const l=Math.round(o.loaded/o.total*100);r.style.width=\`\${l}%\`;a.textContent=\`\${l}%\`}});n.addEventListener('load',()=>{try{const o=JSON.parse(n.responseText);if(n.status>=200&&n.status<300&&o.status===1){a.textContent=o.msg;uploadedUrls.push(o.url);updateUrlArea();t.classList.add('success')}else{const i=[o.msg,o.error||'未知错误'].filter(Boolean).join(' | ');a.textContent=i;t.classList.add('error')}}catch(o){a.textContent='✗ 响应解析失败';t.classList.add('error')}});const l=new FormData;l.append('file',e);const s=document.getElementById('filePassword').value;s&&l.append('password',s);n.open('POST','/upload');n.send(l)}function createPreview(e){const t=document.createElement('div');t.className='preview-item';if(e.type.startsWith('image/')){const n=document.createElement('img');n.src=URL.createObjectURL(e);t.appendChild(n)}const n=document.createElement('div');return n.className='info',n.innerHTML=\`<div>\${e.name}</div><div>\${formatSize(e.size)}</div><div class="progress-bar"><div class="progress-track"></div><span class="progress-text">0%</span></div>\`,t.appendChild(n),t}function formatSize(e){if(e===0)return'0 B';const t=['B','KB','MB','GB','TB'],n=Math.floor(Math.log(e)/Math.log(1024));return\`\${(e/Math.pow(1024,n)).toFixed(2)} \${t[n]}\`}function updateUrlArea(){urlArea.value=uploadedUrls.join('\\n')}function copyUrls(e){if(uploadedUrls.length===0){alert('没有可复制的链接');return}let t='';switch(e){case'url':t=uploadedUrls.join('\\n');break;case'markdown':t=uploadedUrls.map(n=>\`![](\${n})\`).join('\\n');break;case'html':t=uploadedUrls.map(n=>\`<img src="\${n}" />\`).join('\\n')}navigator.clipboard.writeText(t);alert('已复制到剪贴板')}</script></body></html>`;
}

function generateAdminPage(fileCards, modalHtml, stats) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>文件管理</title><style>body{font-family:Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;background-size:cover;background-position:center;transition:background-image 1s ease-in-out}.container{max-width:1200px;margin:0 auto}.header{background:rgba(255,255,255,.8);backdrop-filter:blur(10px);padding:20px 30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap}.header-left{display:flex;align-items:center;gap:20px}h2{margin:0}#stats{color:red;font-weight:bold;font-size:1.2em}.header-right{display:flex;align-items:center;gap:15px}.search{padding:8px;border:1px solid #ddd;border-radius:4px;width:250px}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:20px}.file-card{background:rgba(255,255,255,.8);border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);overflow:hidden;position:relative;transition:transform .2s,box-shadow .2s}.file-card.selected{transform:translateY(-5px);box-shadow:0 8px 20px rgba(0,123,255,.3)}.file-preview{height:150px;background:rgba(230,230,230,.5);display:flex;align-items:center;justify-content:center}.file-preview img,.file-preview video{max-width:100%;max-height:100%;object-fit:contain}.file-info{padding:10px;font-size:14px;word-break:break-all}.file-name{font-weight:bold;margin-bottom:5px}.file-password{cursor:pointer;color:#0056b3;font-size:12px;margin-top:5px}.file-actions{padding:10px;border-top:1px solid #eee;display:flex;justify-content:space-around;align-items:center;font-size:12px}.file-checkbox{position:absolute;left:10px;top:10px;z-index:10;transform:scale(1.2)}.btn{padding:5px 10px;border:none;border-radius:4px;cursor:pointer}.btn-delete{background:#dc3545;color:#fff}.btn-copy{background:#007bff;color:#fff}.btn-edit{background:#ffc107;color:#000}.btn-down{background:#28a745;color:#fff;text-decoration:none}.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);justify-content:center;align-items:center;z-index:1000}.modal-content{background:#fff;padding:20px;border-radius:10px;text-align:center;box-shadow:0 2px 10px rgba(0,0,0,.2);width:90%;max-width:400px}.modal-content h3{margin-top:0}#qrcode{margin:15px 0}.url-container{display:flex;align-items:center;margin-top:15px;border:1px solid #ccc;border-radius:5px;padding:5px}#qrUrlLink{flex-grow:1;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-decoration:none;color:#007bff}#qrUrlCopyBtn{margin-left:10px;padding:5px 10px;background:#007bff;color:#fff;border:none;border-radius:5px;cursor:pointer}.modal-close{padding:8px 20px;background:#6c757d;color:#fff;border:none;border-radius:5px;cursor:pointer;margin-top:15px}.form-group{margin-bottom:15px;text-align:left}.form-group label{display:block;margin-bottom:5px}.form-group input{width:100%;padding:8px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}.modal-buttons{display:flex;justify-content:flex-end;gap:10px;margin-top:20px}.btn-save{background:#28a745;color:#fff}</style></head><body><div class="container"><div class="header"><div class="header-left"><h2>文件管理</h2><div id="stats">共 ${stats.count} 个文件，总大小 ${stats.size}</div></div><div class="header-right"><button id="deleteSelectedBtn" class="btn btn-delete" style="display:none">删除选中</button><input type="checkbox" id="selectAllCheckbox" title="全选"><a href="/upload" class="backup" style="text-decoration:none;color:#007bff">返回上传</a><input type="text" class="search" placeholder="搜索文件..." id="searchInput"></div></div><div class="grid" id="fileGrid">${fileCards}</div>${modalHtml}</div><script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script><script>async function setBingBackground(){try{const e=await fetch('/bing'),t=await e.json();if(t.status&&t.data.length>0){const n=Math.floor(Math.random()*t.data.length);document.body.style.backgroundImage=\`url(\${t.data[n].url})\`}}catch(e){console.error('获取背景图失败:',e)}}setBingBackground();setInterval(setBingBackground,36e5);document.getElementById('searchInput').addEventListener('input',e=>{const t=e.target.value.toLowerCase();document.querySelectorAll('.file-card').forEach(n=>{const o=n.querySelector('.file-name').textContent.toLowerCase();n.style.display=o.includes(t)?'':'none'})});function showQRCode(e){const t=document.getElementById('qrModal'),n=document.getElementById('qrcode');n.innerHTML='';new QRCode(n,{text:e,width:200,height:200});const o=document.getElementById('qrUrlLink');o.href=e;o.textContent=e;document.getElementById('qrUrlCopyBtn').onclick=()=>navigator.clipboard.writeText(e).then(()=>alert('链接已复制'));t.style.display='flex'}function closeModal(e){document.getElementById(e).style.display='none'}window.onclick=e=>{if(e.target.classList.contains('modal'))e.target.style.display='none'};async function deleteFile(e){if(confirm('确定要删除这个文件吗？'))await performDelete([e])}const selectAllCheckbox=document.getElementById('selectAllCheckbox'),deleteSelectedBtn=document.getElementById('deleteSelectedBtn'),fileCheckboxes=document.querySelectorAll('.file-checkbox');function updateSelectionState(){const e=document.querySelectorAll('.file-checkbox:checked'),t=document.querySelectorAll('.file-checkbox');if(e.length>0){deleteSelectedBtn.style.display='inline-block';deleteSelectedBtn.textContent=\`删除选中 (\${e.length})\`}else deleteSelectedBtn.style.display='none';if(t.length>0){if(e.length===t.length){selectAllCheckbox.checked=true;selectAllCheckbox.indeterminate=false}else if(e.length>0){selectAllCheckbox.checked=false;selectAllCheckbox.indeterminate=true}else{selectAllCheckbox.checked=false;selectAllCheckbox.indeterminate=false}}fileCheckboxes.forEach(n=>{n.closest('.file-card').classList.toggle('selected',n.checked)})}selectAllCheckbox.addEventListener('change',e=>{fileCheckboxes.forEach(t=>{t.checked=e.target.checked});updateSelectionState()});fileCheckboxes.forEach(e=>{e.addEventListener('change',updateSelectionState)});deleteSelectedBtn.addEventListener('click',async()=>{const e=Array.from(document.querySelectorAll('.file-checkbox:checked')).map(t=>t.closest('.file-card').dataset.url);if(e.length===0){alert('请先选择要删除的文件');return}if(confirm(\`确定要删除选中的 \${e.length} 个文件吗？\\n此操作不可恢复！\`))await performDelete(e)});async function performDelete(e){try{const t=await fetch('/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({urls:e})});if(!t.ok)throw new Error((await t.json()).error||'删除请求失败');const n=await t.json();let o=0;n.results.forEach(l=>{if(l.success){const c=document.querySelector(\`[data-url="\${l.url}"]\`);c&&c.remove();o++}else console.error(\`删除 \${l.url} 失败: \`,l.error)});alert(\`删除操作完成: \${o}个成功, \${e.length-o}个失败。\`)}catch(t){alert('删除失败: '+t.message)}finally{updateSelectionState()}}updateSelectionState();function copyPassword(e){navigator.clipboard.writeText(e).then(()=>alert('密码已复制'))}function showEditModal(e,t,n){document.getElementById('editFileUrl').value=e;document.getElementById('editFileName').value=t;document.getElementById('editFilePassword').value=n;document.getElementById('editModal').style.display='flex'}async function handleUpdateFile(){const e=document.getElementById('editFileUrl').value,t=document.getElementById('editFileName').value,n=document.getElementById('editFilePassword').value;try{const o=await fetch('/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:e,fileName:t,password:n})}),l=await o.json();if(l.success){alert('更新成功');const c=document.querySelector(\`[data-url="\${e}"]\`);if(c){c.querySelector('.file-name').textContent=t;c.dataset.name=t;c.dataset.password=n;const d=c.querySelector('.file-password');if(n){if(d)d.textContent=\`密码: \${n}\`;else{const a=document.createElement('div');a.className='file-password';a.title='点击复制密码';a.textContent=\`密码: \${n}\`;a.onclick=()=>copyPassword(n);c.querySelector('.file-info').appendChild(a)}}else d&&d.remove()}}else alert('更新失败: '+l.message)}catch(o){alert('更新失败: '+o.message)}finally{closeModal('editModal')}}</script></body></html>`;
}

function generatePasswordPromptPage(url, error = false) {
  const errorMessage = error ? '<p class="error">密码错误，请重试</p>' : '';
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>密码保护</title><style>body{display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;background:#f0f2f5}.container{padding:40px;background:#fff;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.1);text-align:center}h2{margin-bottom:20px}input{width:100%;padding:10px;margin-bottom:20px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}button{width:100%;padding:10px;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer}.error{color:red}</style></head><body><div class="container"><h2>此文件受密码保护</h2><p>请输入密码以访问</p>${errorMessage}<form method="POST" action="${url}"><input type="password" name="password" required><button type="submit">确认</button></form></div></body></html>`;
}
