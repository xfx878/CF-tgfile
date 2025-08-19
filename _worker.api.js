// 由于tg的限制，虽然可以上传超过20M的文件，但无法返回直链地址
// 因此修改代码，当文件大于20MB时，直接阻止上传

// HTML模板加载器 - 为了代码的独立性，我将它内联到主文件中
const templates = {
  'login.html': `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{pageTitle}}</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f7f6; }
            .login-container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 8px 16px rgba(0,0,0,0.1); text-align: center; }
            h1 { color: #333; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background-color: #007bff; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; }
            button:hover { background-color: #0056b3; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>{{pageTitle}}</h1>
            <input type="text" id="username" placeholder="用户名" required>
            <input type="password" id="password" placeholder="密码" required>
            <button onclick="login()">登录</button>
        </div>
        <script>
            async function login() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                if (response.ok) {
                    window.location.href = '/';
                } else {
                    alert('登录失败，请检查用户名和密码');
                }
            }
        </script>
    </body>
    </html>
  `,
  'upload.html': `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{pageTitle}}</title>
        <style>
            body { font-family: sans-serif; margin: 0; background-color: #f0f2f5; color: #333; }
            .navbar { background-color: #fff; padding: 10px 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
            .navbar a { color: #007bff; text-decoration: none; font-weight: 500; margin: 0 15px; }
            .container { max-width: 800px; margin: 40px auto; padding: 20px; background: #fff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
            .upload-area { border: 2px dashed #007bff; border-radius: 8px; padding: 40px; text-align: center; cursor: pointer; transition: background-color 0.3s; }
            .upload-area:hover { background-color: #f8f9fa; }
            .upload-area p { margin: 0; font-size: 18px; color: #555; }
            #file-input { display: none; }
            .password-input { margin-top: 20px; }
            .password-input input { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
            .progress-bar { width: 100%; background-color: #e9ecef; border-radius: 4px; margin-top: 20px; display: none; }
            .progress { width: 0; height: 20px; background-color: #28a745; border-radius: 4px; text-align: center; color: white; line-height: 20px; }
            .result { margin-top: 20px; }
            .result input { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
            footer { text-align: center; margin-top: 40px; padding: 20px; color: #777; }
        </style>
    </head>
    <body>
        <div class="navbar">
            <div>
                <a href="/">文件上传</a>
                <a href="/admin">文件管理</a>
            </div>
            <div>
                <a href="{{githubUrl}}" target="_blank">{{githubName}}</a>
                <a href="{{blogUrl}}" target="_blank">{{blogName}}</a>
            </div>
        </div>
        <div class="container">
            <div class="upload-area" id="upload-area">
                <p>点击或拖拽文件到此区域上传</p>
                <p id="file-limit-info"></p>
            </div>
            <div class="password-input">
                <input type="text" id="password" placeholder="设置访问密码 (可选)">
            </div>
            <input type="file" id="file-input">
            <div class="progress-bar" id="progress-bar">
                <div class="progress" id="progress">0%</div>
            </div>
            <div class="result" id="result" style="display:none;">
                <p>上传成功！文件链接：</p>
                <input type="text" id="file-url" readonly>
            </div>
        </div>
        <footer>&copy; 2024 TG File Uploader</footer>
        <script>
            const uploadArea = document.getElementById('upload-area');
            const fileInput = document.getElementById('file-input');
            const passwordInput = document.getElementById('password');
            const progressBar = document.getElementById('progress-bar');
            const progress = document.getElementById('progress');
            const resultDiv = document.getElementById('result');
            const fileUrlInput = document.getElementById('file-url');
            const fileLimitInfo = document.getElementById('file-limit-info');

            fetch('/config').then(res => res.json()).then(config => {
                fileLimitInfo.textContent = '单文件大小限制: ' + config.maxSizeMB + 'MB';
            });

            uploadArea.addEventListener('click', () => fileInput.click());
            uploadArea.addEventListener('dragover', (e) => { e.preventDefault(); uploadArea.style.backgroundColor = '#e9ecef'; });
            uploadArea.addEventListener('dragleave', () => { uploadArea.style.backgroundColor = 'transparent'; });
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.style.backgroundColor = 'transparent';
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    fileInput.files = files;
                    uploadFile(files[0]);
                }
            });
            fileInput.addEventListener('change', () => {
                if (fileInput.files.length > 0) {
                    uploadFile(fileInput.files[0]);
                }
            });

            function uploadFile(file) {
                const formData = new FormData();
                formData.append('file', file);
                formData.append('password', passwordInput.value);

                progressBar.style.display = 'block';
                progress.style.width = '0%';
                progress.textContent = '0%';
                resultDiv.style.display = 'none';

                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/upload', true);

                xhr.upload.onprogress = function(e) {
                    if (e.lengthComputable) {
                        const percentComplete = (e.loaded / e.total) * 100;
                        progress.style.width = percentComplete.toFixed(2) + '%';
                        progress.textContent = percentComplete.toFixed(2) + '%';
                    }
                };

                xhr.onload = function() {
                    if (xhr.status === 200) {
                        const response = JSON.parse(xhr.responseText);
                        fileUrlInput.value = response.url;
                        resultDiv.style.display = 'block';
                    } else {
                        const error = JSON.parse(xhr.responseText);
                        alert('上传失败: ' + error.error);
                        progressBar.style.display = 'none';
                    }
                };
                
                xhr.onerror = function() {
                    alert('网络错误，上传失败。');
                    progressBar.style.display = 'none';
                };

                xhr.send(formData);
            }
        </script>
    </body>
    </html>
  `,
  'admin.html': `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{pageTitle}}</title>
        <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
        <style>
            body { font-family: sans-serif; margin: 0; background-color: #f0f2f5; }
            .navbar { background-color: #fff; padding: 10px 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
            .navbar a { color: #007bff; text-decoration: none; font-weight: 500; }
            .container { max-width: 1200px; margin: 20px auto; padding: 20px; }
            .admin-header { background: #fff; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; }
            .stats, .actions, .search-box { display: flex; align-items: center; gap: 15px; }
            .stats span { font-size: 14px; color: #555; background: #f0f2f5; padding: 5px 10px; border-radius: 5px; }
            .stats .important-stat { color: red; font-weight: bold; font-size: 1.1em; }
            .actions label { display: flex; align-items: center; cursor: pointer; }
            .btn { padding: 8px 12px; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-block; text-align: center; }
            .btn-danger { background-color: #dc3545; color: white; }
            .btn-danger:hover { background-color: #c82333; }
            .search-box input { padding: 8px; border: 1px solid #ccc; border-radius: 5px; }
            .file-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 20px; }
            .file-card { background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); overflow: hidden; display: flex; flex-direction: column; }
            .file-card .file-select { padding: 5px 10px; background: #f8f9fa; border-bottom: 1px solid #eee; }
            .file-preview { height: 150px; display: flex; justify-content: center; align-items: center; background: #f0f2f5; }
            .file-preview img, .file-preview video { max-width: 100%; max-height: 100%; object-fit: contain; }
            .file-info { padding: 10px; flex-grow: 1; }
            .file-info div { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 13px; color: #666; margin-bottom: 5px; }
            .file-info div:first-child { font-weight: bold; color: #333; }
            .password-info { cursor: pointer; }
            .file-actions { display: flex; justify-content: space-around; padding: 10px; border-top: 1px solid #eee; }
            .file-actions .btn { flex: 1; margin: 0 5px; padding: 6px; font-size: 12px; }
            .btn-copy { background-color: #28a745; color: white; }
            .btn-edit { background-color: #17a2b8; color: white; }
            .btn-down { background-color: #007bff; color: white; }
            .btn-delete { background-color: #ffc107; color: #212529; }
            .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); justify-content: center; align-items: center; }
            .modal-content { background: white; padding: 20px; border-radius: 8px; text-align: center; }
            #qrcode { padding: 10px; }
            .qr-link-container { display: flex; align-items: center; justify-content: center; gap: 10px; margin-top: 10px; }
            .qr-link-container a { color: #007bff; }
            .modal-buttons { margin-top: 15px; }
            .edit-modal-content input { width: 90%; padding: 8px; margin-bottom: 10px; }
            /* Custom Alert/Confirm Modal */
            .custom-modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 2000; opacity: 0; pointer-events: none; transition: opacity 0.3s; }
            .custom-modal-overlay.active { opacity: 1; pointer-events: auto; }
            .custom-modal { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); text-align: center; max-width: 350px; transform: scale(0.9); transition: transform 0.3s; }
            .custom-modal.active { transform: scale(1); }
            .custom-modal p { margin: 0 0 20px; font-size: 16px; }
            .custom-modal-buttons { display: flex; justify-content: center; gap: 10px; }
            .custom-modal-buttons button { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
            .modal-btn-confirm { background-color: #dc3545; color: white; }
            .modal-btn-cancel { background-color: #6c757d; color: white; }
            .modal-btn-ok { background-color: #007bff; color: white; }
        </style>
    </head>
    <body>
        <div class="navbar">
            <a href="/">文件上传</a>
            <a href="/admin">文件管理</a>
        </div>
        <div class="container">
            <div class="admin-header">
                <div class="stats">
                    <span class="important-stat">文件总数: {{totalFiles}}</span>
                    <span class="important-stat">总大小: {{totalSize}}</span>
                </div>
                <div class="actions">
                    <label><input type="checkbox" id="selectAllCheckbox"> 全选</label>
                    <button id="deleteSelectedBtn" class="btn btn-danger">删除选中</button>
                </div>
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="搜索文件名...">
                    <button id="searchBtn" class="btn btn-down">搜索</button>
                </div>
            </div>
            <div class="file-grid" id="fileGrid">
                {{{FILE_CARDS}}}
            </div>
        </div>
        
        {{{MODALS}}}

        <!-- Custom Alert/Confirm Modal Structure -->
        <div id="custom-modal-overlay" class="custom-modal-overlay">
            <div id="custom-modal" class="custom-modal">
                <p id="custom-modal-message"></p>
                <div id="custom-modal-buttons" class="custom-modal-buttons"></div>
            </div>
        </div>

        <script>
            let currentUrlToCopy = '';
            const qrModal = document.getElementById('qrModal');
            const editModal = document.getElementById('editModal');
            const qrcodeContainer = document.getElementById('qrcode');
            const qrLink = document.getElementById('qrLink');
            let qrcode = new QRCode(qrcodeContainer, { width: 200, height: 200 });

            function showQRCode(url) {
                currentUrlToCopy = url;
                qrcode.makeCode(url);
                qrLink.href = url;
                qrLink.textContent = url;
                qrModal.style.display = 'flex';
            }
            
            function showEditModal(url, currentName, currentPassword) {
                document.getElementById('edit-url').value = url;
                document.getElementById('edit-name').value = currentName;
                document.getElementById('edit-password').value = currentPassword || '';
                editModal.style.display = 'flex';
            }

            function closeModal(modalId) {
                document.getElementById(modalId).style.display = 'none';
                if (modalId === 'qrModal') qrcode.clear();
            }

            function copyToClipboard(text, message) {
                 navigator.clipboard.writeText(text).then(() => {
                    showCustomAlert(message || '已复制到剪贴板');
                }, () => {
                    showCustomAlert('复制失败');
                });
            }

            async function handleUpdateFile() {
                const url = document.getElementById('edit-url').value;
                const newName = document.getElementById('edit-name').value;
                const newPassword = document.getElementById('edit-password').value;
                
                try {
                    const response = await fetch('/update', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url, newName, newPassword })
                    });
                    const result = await response.json();
                    if (response.ok && result.success) {
                        showCustomAlert('更新成功').then(() => location.reload());
                    } else {
                        throw new Error(result.error || '更新失败');
                    }
                } catch (error) {
                    showCustomAlert('更新失败: ' + error.message);
                }
            }

            // --- Custom Modal Functions ---
            const modalOverlay = document.getElementById('custom-modal-overlay');
            const modal = document.getElementById('custom-modal');
            const modalMessage = document.getElementById('custom-modal-message');
            const modalButtons = document.getElementById('custom-modal-buttons');

            function showCustomAlert(message) {
                return new Promise(resolve => {
                    modalMessage.textContent = message;
                    modalButtons.innerHTML = '<button class="modal-btn-ok">确定</button>';
                    modalOverlay.classList.add('active');
                    modal.classList.add('active');

                    modalButtons.querySelector('.modal-btn-ok').onclick = () => {
                        modalOverlay.classList.remove('active');
                        modal.classList.remove('active');
                        resolve();
                    };
                });
            }
            
            function showCustomConfirm(message) {
                return new Promise(resolve => {
                    modalMessage.textContent = message;
                    modalButtons.innerHTML = '<button class="modal-btn-confirm">确认</button><button class="modal-btn-cancel">取消</button>';
                    modalOverlay.classList.add('active');
                    modal.classList.add('active');

                    modalButtons.querySelector('.modal-btn-confirm').onclick = () => {
                        modalOverlay.classList.remove('active');
                        modal.classList.remove('active');
                        resolve(true);
                    };
                    modalButtons.querySelector('.modal-btn-cancel').onclick = () => {
                        modalOverlay.classList.remove('active');
                        modal.classList.remove('active');
                        resolve(false);
                    };
                });
            }
            
            async function deleteFile(url) {
                const confirmed = await showCustomConfirm('确定要删除这个文件吗？');
                if (confirmed) {
                    try {
                        const response = await fetch('/delete', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ url })
                        });
                        const result = await response.json();
                        if (response.ok && result.success) {
                            showCustomAlert('删除成功').then(() => location.reload());
                        } else {
                            throw new Error(result.error || '删除失败');
                        }
                    } catch (error) {
                        showCustomAlert('删除失败: ' + error.message);
                    }
                }
            }

            document.getElementById('selectAllCheckbox').addEventListener('change', (e) => {
                document.querySelectorAll('.file-checkbox').forEach(checkbox => {
                    checkbox.checked = e.target.checked;
                });
            });

            document.getElementById('deleteSelectedBtn').addEventListener('click', async () => {
                const selectedCheckboxes = document.querySelectorAll('.file-checkbox:checked');
                if (selectedCheckboxes.length === 0) {
                    showCustomAlert('请先选择要删除的文件。');
                    return;
                }
                
                const confirmed = await showCustomConfirm(\`确定要删除选中的 \${selectedCheckboxes.length} 个文件吗？\`);
                if (confirmed) {
                    let failedDeletes = 0;
                    for (const checkbox of selectedCheckboxes) {
                        const url = checkbox.dataset.url;
                        try {
                            const response = await fetch('/delete', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ url })
                            });
                            if (!response.ok) failedDeletes++;
                        } catch (error) {
                            failedDeletes++;
                        }
                    }
                    if (failedDeletes > 0) {
                        showCustomAlert(\`\${selectedCheckboxes.length - failedDeletes} 个文件删除成功，\${failedDeletes} 个失败。\`).then(() => location.reload());
                    } else {
                        showCustomAlert('选中的文件已全部删除。').then(() => location.reload());
                    }
                }
            });

            // 搜索功能
            const performSearch = async () => {
                const query = document.getElementById('searchInput').value;
                location.href = \`/admin?search=\${encodeURIComponent(query)}\`;
            };

            document.getElementById('searchBtn').addEventListener('click', performSearch);
            document.getElementById('searchInput').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    performSearch();
                }
            });
        </script>
    </body>
    </html>
  `,
  'password.html': `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>需要密码</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f7f6; }
            .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 8px 16px rgba(0,0,0,0.1); text-align: center; }
            h1 { color: #333; }
            p { color: #d9534f; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 8px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background-color: #007bff; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; }
            button:hover { background-color: #0056b3; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>请输入密码访问文件</h1>
            <form method="GET">
                <input type="password" name="password" placeholder="密码" required>
                <button type="submit">确认</button>
            </form>
            {{ERROR_MESSAGE}}
        </div>
    </body>
    </html>
  `
};

async function loadTemplate(name) {
  return templates[name] || '';
}

function render(template, data) {
  return template.replace(/\{\{\{?(\w+)\}\}?}/g, (match, key) => {
    return data[key] || '';
  });
}

// 数据库初始化函数
async function initDatabase(config) {
  await config.database.prepare(`
    CREATE TABLE IF NOT EXISTS files (
      url TEXT PRIMARY KEY,
      fileId TEXT NOT NULL,
      message_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
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
      maxSizeMB: Number(env.MAX_SIZE_MB) || 20, // 上传单文件大小默认为20M
      apiKey: env.API_KEY
    };

    // 初始化数据库
    await initDatabase(config);
    // 路由处理
    const url = new URL(request.url);
    const { pathname } = url;
    
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
  const html = await generateLoginPage();  // 如果是GET请求，返回登录页面
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
    const html = await generateUploadPage();
    return new Response(html, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' }
    });
  }

  try {
    const formData = await request.formData();
    const file = formData.get('file');
    const password = formData.get('password');
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

    // 对于所有其他类型，都使用 sendDocument
    if (!typeMap[mainType]) {
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
    const timestamp = new Date().toISOString();
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
    let statusCode = 500;
    if (error.message.includes(`文件超过${config.maxSizeMB}MB限制`)) statusCode = 400;
    else if (error.message.includes('Telegram参数配置错误')) statusCode = 502;
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

  const url = new URL(request.url);
  const searchQuery = url.searchParams.get('search');
  
  let files;
  if (searchQuery) {
    const searchPattern = `%${searchQuery}%`;
    files = await config.database.prepare(
      `SELECT * FROM files WHERE file_name LIKE ? COLLATE NOCASE ORDER BY created_at DESC`
    ).bind(searchPattern).all();
  } else {
    files = await config.database.prepare(
      `SELECT * FROM files ORDER BY created_at DESC`
    ).all();
  }

  const fileList = files.results || [];
  
  const totalFiles = fileList.length;
  const totalSize = fileList.reduce((sum, file) => sum + (file.file_size || 0), 0);
  const formattedTotalSize = formatSize(totalSize);

  const fileCards = fileList.map(file => {
    const fileName = file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const passwordDisplay = file.password ? `<div class="password-info" onclick="copyToClipboard('${file.password}', '密码已复制')">密码: ${file.password}</div>` : '<div>无密码</div>';
    
    return `
      <div class="file-card" data-url="${file.url}">
        <div class="file-select">
          <input type="checkbox" class="file-checkbox" data-url="${file.url}">
        </div>
        <div class="file-preview">
          ${getPreviewHtml(file.url)}
        </div>
        <div class="file-info">
          <div>${fileName}</div>
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

  const modals = `
    <div id="qrModal" class="modal">
      <div class="modal-content">
        <div id="qrcode"></div>
        <div class="qr-link-container">
           <a id="qrLink" href="#" target="_blank"></a>
           <button class="btn btn-copy" onclick="copyToClipboard(currentUrlToCopy, '链接已复制')">复制</button>
        </div>
        <div class="modal-buttons">
          <button class="btn btn-delete" onclick="closeModal('qrModal')">关闭</button>
        </div>
      </div>
    </div>
    <div id="editModal" class="modal">
        <div class="modal-content edit-modal-content">
            <h3>编辑文件信息</h3>
            <input type="hidden" id="edit-url">
            <input type="text" id="edit-name" placeholder="文件名">
            <input type="text" id="edit-password" placeholder="新密码 (留空则无密码)">
            <div class="modal-buttons">
                <button class="btn btn-down" onclick="handleUpdateFile()">保存</button>
                <button class="btn btn-delete" onclick="closeModal('editModal')">取消</button>
            </div>
        </div>
    </div>
  `;

  const html = await generateAdminPage(fileCards, modals, totalFiles, formattedTotalSize);
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  });
}

// 处理文件信息更新
async function handleUpdateRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    if (request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405 });
    }
    try {
        const { url, newName, newPassword } = await request.json();
        if (!url || !newName) {
            throw new Error('缺少必要参数');
        }

        await config.database.prepare(
            `UPDATE files SET file_name = ?, password = ? WHERE url = ?`
        ).bind(newName, newPassword || null, url).run();

        return new Response(JSON.stringify({ success: true, message: '更新成功' }), {
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        console.error(`[Update Error] ${error.message}`);
        return new Response(JSON.stringify({ error: error.message }), { status: 500 });
    }
}


// 支持预览的文件类型
function getPreviewHtml(url) {
  const ext = (url.split('.').pop() || '').toLowerCase();
  const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'].includes(ext);
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
  const url = new URL(request.url);
  const requestUrl = `${url.origin}${url.pathname}`;
  const cache = caches.default;
  const cacheKey = new Request(requestUrl, request);

  try {
    const file = await config.database.prepare(
      `SELECT * FROM files WHERE url = ?`
    ).bind(requestUrl).first();

    if (!file) {
      return new Response('文件不存在', { status: 404 });
    }

    // 密码保护逻辑
    if (file.password) {
        const providedPassword = url.searchParams.get('password');
        if (providedPassword !== file.password) {
            const errorMessage = providedPassword ? '<p>密码错误，请重试。</p>' : '';
            const passwordPage = await loadTemplate('password.html');
            return new Response(render(passwordPage, { ERROR_MESSAGE: errorMessage }), {
                status: 401,
                headers: { 'Content-Type': 'text/html;charset=UTF-8' }
            });
        }
    }

    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) return cachedResponse;

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
        'Content-Type': file.mime_type || getContentType(requestUrl.split('.').pop().toLowerCase()),
        'Cache-Control': 'public, max-age=31536000',
        'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(file.file_name || '')}`
      }
    });

    await cache.put(cacheKey, response.clone());
    return response;

  } catch (error) {
    console.error(`[File Request Error] ${error.message} for ${request.url}`);
    return new Response('服务器内部错误', { status: 500 });
  }
}

// 处理文件删除
async function handleDeleteRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  try {
    const { url } = await request.json();
    if (!url) throw new Error('无效的URL');

    const file = await config.database.prepare('SELECT message_id FROM files WHERE url = ?').bind(url).first();    
    if (!file) throw new Error('文件不存在');

    const deleteResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`);
    const deleteData = await deleteResponse.json();
    
    // 即使TG删除失败也继续删除数据库记录，因为消息可能已被手动删除
    if (!deleteResponse.ok) {
        console.warn(`TG消息删除失败: ${deleteData.description}`);
    }

    await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
    
    return new Response(JSON.stringify({ success: true, message: '文件删除成功' }), { headers: { 'Content-Type': 'application/json' }});

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }
}

// 支持上传的文件类型
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
    // 添加更多常见格式
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

async function handleBingImagesRequest(request, config) {
  const cache = caches.default;
  const cacheKey = new Request('https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=5', request);
  
  const cachedResponse = await cache.match(cacheKey);
  if (cachedResponse) return cachedResponse;
  
  try {
    const res = await fetch(cacheKey.url);
    if (!res.ok) throw new Error(`Bing API 请求失败: ${res.status}`);
    
    const bingData = await res.json();
    const images = bingData.images.map(image => ({ url: `https://cn.bing.com${image.url}` }));
    
    const response = new Response(JSON.stringify({ status: true, data: images }), { 
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=21600',
        'Access-Control-Allow-Origin': '*' 
      }
    });
    
    await cache.put(cacheKey, response.clone());
    return response;
  } catch (error) {
    console.error('请求 Bing API 失败:', error);
    return new Response(JSON.stringify({ status: false, error: error.message }), { status: 500 });
  }
}

// 文件大小计算函数
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${units[i]}`;
}

// 页面生成函数
async function generateLoginPage() {
  const baseHtml = await loadTemplate('login.html');
  return render(baseHtml, { pageTitle: '用户登录' });
}

async function generateUploadPage() {
  const baseHtml = await loadTemplate('upload.html');
  return render(baseHtml, { 
    pageTitle: '文件上传',
    githubUrl:'https://github.com/yutian81/CF-tgfile',
    githubName:'GitHub',
    blogUrl:'https://blog.811520.xyz/',
    blogName:'Blog'
  });
}

async function generateAdminPage(fileCards, modals, totalFiles, totalSize) {
  const baseHtml = await loadTemplate('admin.html');
  return render(baseHtml, {
    pageTitle: '文件管理',
    FILE_CARDS: fileCards,
    MODALS: modals,
    totalFiles: totalFiles,
    totalSize: totalSize
  });
}
