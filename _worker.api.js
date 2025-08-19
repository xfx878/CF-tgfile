// 核心逻辑：使用 Telegram 作为文件存储后端，Cloudflare Worker 提供访问接口，D1 数据库存储文件元数据。
// 更新日期：2024-08-20
// 主要功能：文件上传、下载、管理、分享、API接口。
// 新增功能：文件统计、全选、批量删除。

/**
 * 数据库初始化函数
 * @param {object} config - 包含数据库实例的配置对象
 */
async function initDatabase(config) {
  // 创建文件表（如果不存在）
  await config.database.prepare(`
    CREATE TABLE IF NOT EXISTS files (
      url TEXT PRIMARY KEY,
      fileId TEXT NOT NULL,
      message_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      file_name TEXT,
      file_size INTEGER,
      mime_type TEXT
    )
  `).run();
}

/**
 * 主入口点，处理所有传入的请求
 */
export default {
  async fetch(request, env) {
    // 从环境变量加载配置
    const config = {
      domain: env.DOMAIN, // 您的域名
      database: env.DATABASE, // D1 数据库绑定
      username: env.USERNAME, // 登录用户名
      password: env.PASSWORD, // 登录密码
      enableAuth: env.ENABLE_AUTH === 'true', // 是否启用认证
      tgBotToken: env.TG_BOT_TOKEN, // Telegram Bot Token
      tgChatId: env.TG_CHAT_ID, // Telegram 聊天 ID
      cookie: Number(env.COOKIE) || 7, // Cookie 有效期（天）
      maxSizeMB: Number(env.MAX_SIZE_MB) || 20, // 最大上传文件大小 (MB)
      apiKey: env.API_KEY // API 密钥
    };

    // 确保数据库已初始化
    await initDatabase(config);

    const { pathname } = new URL(request.url);

    // 提供给前端的公共配置
    if (pathname === '/config') {
      const safeConfig = { maxSizeMB: config.maxSizeMB };
      return new Response(JSON.stringify(safeConfig), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // API 路由
    const apiRoutes = {
      '^/api/upload$': () => handleApiUpload(request, config),
      '^/api/files$': () => handleApiFileList(request, config),
      '^/api/files/([^/]+)$': (matches) => handleApiFileOps(request, config, matches[1]),
      '^/api/search$': () => handleApiSearch(request, config)
    };

    for (const [pattern, handler] of Object.entries(apiRoutes)) {
      const match = pathname.match(new RegExp(pattern));
      if (match) {
        return await handler(match);
      }
    }

    // 页面路由
    const pageRoutes = {
      '/': () => handleAuthRequest(request, config),
      '/login': () => handleLoginRequest(request, config),
      '/upload': () => handleUploadRequest(request, config),
      '/admin': () => handleAdminRequest(request, config),
      '/delete': () => handleDeleteRequest(request, config),
      '/delete-bulk': () => handleBulkDeleteRequest(request, config), // 新增：批量删除路由
      '/search': () => handleSearchRequest(request, config),
      '/bing': () => handleBingImagesRequest(request)
    };

    const handler = pageRoutes[pathname];
    if (handler) {
      return await handler();
    }

    // 如果没有匹配的路由，则视为文件请求
    return await handleFileRequest(request, config);
  }
};


// --- API 处理函数 ---

/**
 * API 认证中间件
 * @param {Request} request
 * @param {object} config
 * @returns {Response|null}
 */
async function authenticateApi(request, config) {
    const apiKey = request.headers.get('X-API-Key') || new URL(request.url).searchParams.get('api_key');
    if (!config.apiKey || apiKey !== config.apiKey) {
        return new Response(JSON.stringify({ error: 'Unauthorized: Invalid API key' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }
    return null; // 认证通过
}

/**
 * API 文件上传
 */
async function handleApiUpload(request, config) {
    const authError = await authenticateApi(request, config);
    if (authError) return authError;

    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json' } });
    }

    try {
        const formData = await request.formData();
        const file = formData.get('file');
        if (!file) {
            return new Response(JSON.stringify({ error: 'No file provided' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        // 复用现有的上传逻辑
        const uploadResponse = await uploadFileToTelegram(file, config);

        return new Response(JSON.stringify(uploadResponse), {
            status: uploadResponse.status === 1 ? 200 : 500,
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}

/**
 * API 文件列表
 */
async function handleApiFileList(request, config) {
    const authError = await authenticateApi(request, config);
    if (authError) return authError;
    
    try {
        const { searchParams } = new URL(request.url);
        const limit = parseInt(searchParams.get('limit') || '50', 10);
        const offset = parseInt(searchParams.get('offset') || '0', 10);
        
        const { results } = await config.database.prepare(
            `SELECT url, file_name, file_size, mime_type, created_at 
             FROM files 
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?`
        ).bind(limit, offset).all();
        
        return new Response(JSON.stringify({ files: results || [] }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}

/**
 * API 单文件操作 (获取信息/删除)
 */
async function handleApiFileOps(request, config, fileId) {
    const authError = await authenticateApi(request, config);
    if (authError) return authError;

    const fileUrl = `https://${config.domain}/${fileId}`;
    
    if (request.method === 'GET') {
        const file = await config.database.prepare(
            `SELECT url, file_name, file_size, mime_type, created_at 
             FROM files WHERE url = ?`
        ).bind(fileUrl).first();
        
        if (!file) {
            return new Response(JSON.stringify({ error: 'File not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
        }
        return new Response(JSON.stringify(file), { headers: { 'Content-Type': 'application/json' } });

    } else if (request.method === 'DELETE') {
        const deleteResult = await deleteFile(fileUrl, config);
        return new Response(JSON.stringify(deleteResult), {
            status: deleteResult.success ? 200 : 500,
            headers: { 'Content-Type': 'application/json' }
        });
    } else {
        return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json' } });
    }
}

/**
 * API 文件搜索
 */
async function handleApiSearch(request, config) {
    const authError = await authenticateApi(request, config);
    if (authError) return authError;
    
    try {
        const { searchParams } = new URL(request.url);
        const query = searchParams.get('q');
        if (!query) {
            return new Response(JSON.stringify({ error: 'Missing search query parameter "q"' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }
        
        const searchPattern = `%${query}%`;
        const { results } = await config.database.prepare(
            `SELECT url, file_name, file_size, mime_type, created_at 
             FROM files 
             WHERE file_name LIKE ?
             ORDER BY created_at DESC`
        ).bind(searchPattern).all();
        
        return new Response(JSON.stringify({ files: results || [] }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}


// --- 认证与页面路由处理 ---

/**
 * 验证用户身份
 * @param {Request} request
 * @param {object} config
 * @returns {boolean}
 */
function authenticate(request, config) {
    const cookies = request.headers.get("Cookie") || "";
    const authToken = cookies.match(/auth_token=([^;]+)/);
    if (authToken) {
        try {
            const tokenData = JSON.parse(atob(authToken[1]));
            if (Date.now() > tokenData.expiration) {
                return false; // Token 过期
            }
            return tokenData.username === config.username;
        } catch (error) {
            return false; // Token 解析失败
        }
    }
    return false;
}

/**
 * 根路径请求，根据认证状态重定向
 */
async function handleAuthRequest(request, config) {
    if (config.enableAuth) {
        if (!authenticate(request, config)) {
            return Response.redirect(`${new URL(request.url).origin}/login`, 302);
        }
    }
    return Response.redirect(`${new URL(request.url).origin}/upload`, 302);
}

/**
 * 处理登录请求
 */
async function handleLoginRequest(request, config) {
    if (request.method === 'POST') {
        try {
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
                return new Response(JSON.stringify({ success: true, message: "登录成功" }), {
                    status: 200,
                    headers: { "Set-Cookie": cookie, "Content-Type": "application/json" }
                });
            }
        } catch (e) {
            // ignore
        }
        return new Response(JSON.stringify({ success: false, message: "用户名或密码错误" }), { status: 401, headers: { "Content-Type": "application/json" } });
    }
    // GET 请求，返回登录页面
    const html = generateLoginPage();
    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

/**
 * 处理上传页面请求和文件上传逻辑
 */
async function handleUploadRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return Response.redirect(`${new URL(request.url).origin}/login`, 302);
    }

    if (request.method === 'POST') {
        try {
            const formData = await request.formData();
            const file = formData.get('file');
            if (!file) throw new Error('未找到文件');

            const result = await uploadFileToTelegram(file, config);
            const status = result.status === 1 ? 200 : 400;

            return new Response(JSON.stringify(result), {
                status: status,
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (error) {
            return new Response(JSON.stringify({ status: 0, msg: "✘ 上传失败", error: error.message }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    // GET 请求，返回上传页面
    const html = generateUploadPage();
    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

/**
 * 核心上传逻辑
 * @param {File} file
 * @param {object} config
 * @returns {Promise<object>}
 */
async function uploadFileToTelegram(file, config) {
    if (file.size > config.maxSizeMB * 1024 * 1024) {
        return { status: 0, msg: `✘ 上传失败`, error: `文件超过 ${config.maxSizeMB}MB 限制` };
    }

    const ext = (file.name.split('.').pop() || '').toLowerCase();
    const mimeType = getContentType(ext);
    const [mainType] = mimeType.split('/');

    const typeMap = {
        image: { method: 'sendPhoto', field: 'photo' },
        video: { method: 'sendVideo', field: 'video' },
        audio: { method: 'sendAudio', field: 'audio' }
    };
    const { method = 'sendDocument', field = 'document' } = typeMap[mainType] || {};

    const tgFormData = new FormData();
    tgFormData.append('chat_id', config.tgChatId);
    tgFormData.append(field, file, file.name);

    const tgResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/${method}`, {
        method: 'POST',
        body: tgFormData
    });

    if (!tgResponse.ok) {
        const errorData = await tgResponse.text();
        console.error("Telegram API Error:", errorData);
        throw new Error('Telegram API 请求失败，请检查 Bot Token 和 Chat ID');
    }

    const tgData = await tgResponse.json();
    if (!tgData.ok) {
        throw new Error(`Telegram 返回错误: ${tgData.description}`);
    }

    const result = tgData.result;
    const messageId = result.message_id;
    const fileId = result?.document?.file_id ||
                   result?.video?.file_id ||
                   result?.audio?.file_id ||
                   (result.photo && result.photo[result.photo.length - 1]?.file_id);

    if (!fileId || !messageId) {
        throw new Error('无法从 Telegram 获取文件 ID 或消息 ID');
    }

    const timestamp = new Date().toISOString();
    const uniqueId = Date.now();
    const url = `https://${config.domain}/${uniqueId}.${ext}`;

    await config.database.prepare(`
      INSERT INTO files (url, fileId, message_id, created_at, file_name, file_size, mime_type) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(url, fileId, messageId, timestamp, file.name, file.size, file.type || mimeType).run();

    return { status: 1, msg: "✔ 上传成功", url };
}


/**
 * 处理文件管理页面请求
 */
async function handleAdminRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return Response.redirect(`${new URL(request.url).origin}/login`, 302);
    }

    // 获取文件列表
    const { results: fileList = [] } = await config.database.prepare(
        `SELECT url, file_name, file_size, created_at FROM files ORDER BY created_at DESC`
    ).all();

    // 获取统计数据
    const stats = await config.database.prepare(
        `SELECT COUNT(*) as total_files, SUM(file_size) as total_size FROM files`
    ).first();

    const html = generateAdminPage(fileList, stats);
    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

/**
 * 处理文件搜索请求
 */
async function handleSearchRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    }

    try {
        const { query } = await request.json();
        const searchPattern = `%${query}%`;
        const { results } = await config.database.prepare(
            `SELECT url, file_name, file_size, created_at
             FROM files 
             WHERE file_name LIKE ?
             ORDER BY created_at DESC`
        ).bind(searchPattern).all();

        return new Response(JSON.stringify({ files: results || [] }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

/**
 * 处理单个文件删除请求
 */
async function handleDeleteRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    }

    try {
        const { url } = await request.json();
        const result = await deleteFile(url, config);
        return new Response(JSON.stringify(result), {
            status: result.success ? 200 : 500,
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, message: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

/**
 * 新增：处理批量删除请求
 */
async function handleBulkDeleteRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    }

    try {
        const { urls } = await request.json();
        if (!Array.isArray(urls) || urls.length === 0) {
            return new Response(JSON.stringify({ success: false, message: '无效的请求，需要提供URL数组' }), { status: 400 });
        }

        let successCount = 0;
        let failCount = 0;
        const errors = [];

        for (const url of urls) {
            const result = await deleteFile(url, config);
            if (result.success) {
                successCount++;
            } else {
                failCount++;
                errors.push({ url, error: result.message });
            }
        }

        return new Response(JSON.stringify({
            success: failCount === 0,
            message: `批量删除完成：${successCount} 个成功，${failCount} 个失败。`,
            details: { successCount, failCount, errors }
        }), {
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        return new Response(JSON.stringify({ success: false, message: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

/**
 * 核心删除逻辑
 * @param {string} url
 * @param {object} config
 * @returns {Promise<object>}
 */
async function deleteFile(url, config) {
    if (!url || typeof url !== 'string') {
        return { success: false, message: '无效的URL' };
    }

    const file = await config.database.prepare(
        'SELECT message_id FROM files WHERE url = ?'
    ).bind(url).first();

    if (!file) {
        // 如果文件在数据库中不存在，可能已经被删除，直接认为成功
        await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
        return { success: true, message: '文件在数据库中不存在，记录已清理' };
    }

    let tgDeleteError = null;
    try {
        const deleteResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/deleteMessage?chat_id=${config.tgChatId}&message_id=${file.message_id}`);
        const result = await deleteResponse.json();
        if (!result.ok) {
            // 如果消息在TG中找不到，也认为是成功的，因为目标是让它消失
            if (result.description.includes('message to delete not found')) {
                 tgDeleteError = null;
            } else {
                throw new Error(result.description);
            }
        }
    } catch (error) {
        tgDeleteError = error.message;
    }

    // 从数据库中删除记录
    await config.database.prepare('DELETE FROM files WHERE url = ?').bind(url).run();
    // 清理缓存
    await caches.default.delete(new Request(url));

    if (tgDeleteError) {
        return { success: false, message: `数据库记录已删除，但 Telegram 消息删除失败: ${tgDeleteError}` };
    }

    return { success: true, message: '文件删除成功' };
}


// --- 文件服务与缓存 ---

/**
 * 处理文件访问请求，提供缓存
 */
async function handleFileRequest(request, config) {
    const url = request.url;
    const cache = caches.default;
    const cacheKey = new Request(url, request);

    try {
        const cachedResponse = await cache.match(cacheKey);
        if (cachedResponse) {
            return cachedResponse;
        }

        const file = await config.database.prepare(
            `SELECT fileId, file_name, mime_type FROM files WHERE url = ?`
        ).bind(url).first();

        if (!file) {
            return new Response('文件不存在', { status: 404 });
        }

        const tgFileResponse = await fetch(`https://api.telegram.org/bot${config.tgBotToken}/getFile?file_id=${file.fileId}`);
        if (!tgFileResponse.ok) throw new Error('无法从Telegram获取文件信息');

        const tgFileData = await tgFileResponse.json();
        const filePath = tgFileData.result?.file_path;
        if (!filePath) throw new Error('无效的文件路径');

        const fileUrl = `https://api.telegram.org/file/bot${config.tgBotToken}/${filePath}`;
        const fileResponse = await fetch(fileUrl);
        if (!fileResponse.ok) throw new Error('下载文件失败');

        const contentType = file.mime_type || getContentType(url.split('.').pop().toLowerCase());
        const response = new Response(fileResponse.body, {
            headers: {
                'Content-Type': contentType,
                'Cache-Control': 'public, max-age=31536000, immutable',
                'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(file.file_name || '')}`
            }
        });

        await cache.put(cacheKey, response.clone());
        return response;

    } catch (error) {
        console.error(`[File Request Error] ${error.message} for ${url}`);
        return new Response('服务器内部错误', { status: 500 });
    }
}

/**
 * 处理 Bing 壁纸 API 请求
 */
async function handleBingImagesRequest(request) {
    const cache = caches.default;
    const cacheKey = new Request('https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=5', request);
    
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) return cachedResponse;
    
    try {
        const res = await fetch(cacheKey.url);
        if (!res.ok) throw new Error(`Bing API 请求失败: ${res.status}`);
        
        const bingData = await res.json();
        const images = bingData.images.map(image => ({ url: `https://cn.bing.com${image.url}` }));
        
        const response = new Response(JSON.stringify({ status: true, message: "操作成功", data: images }), {
            headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'public, max-age=21600', // 缓存6小时
                'Access-Control-Allow-Origin': '*'
            }
        });
        
        await cache.put(cacheKey, response.clone());
        return response;
    } catch (error) {
        console.error('请求 Bing API 失败:', error);
        return new Response('请求 Bing API 失败', { status: 500 });
    }
}


// --- 辅助函数 ---

/**
 * 格式化文件大小
 * @param {number} bytes
 * @returns {string}
 */
function formatSize(bytes) {
    if (bytes === null || isNaN(bytes) || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${units[i]}`;
}

/**
 * 根据文件扩展名获取 MIME 类型
 * @param {string} ext
 * @returns {string}
 */
function getContentType(ext) {
    const types = {
        jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
        webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/x-icon',
        mp4: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime',
        mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg',
        pdf: 'application/pdf', txt: 'text/plain;charset=utf-8', md: 'text/markdown;charset=utf-8',
        zip: 'application/zip', rar: 'application/x-rar-compressed',
        json: 'application/json', xml: 'application/xml',
        js: 'application/javascript', css: 'text/css', html: 'text/html;charset=utf-8',
    };
    return types[ext] || 'application/octet-stream';
}

/**
 * 根据文件 URL 生成预览 HTML
 * @param {string} url
 * @returns {string}
 */
function getPreviewHtml(url) {
    const ext = (url.split('.').pop() || '').toLowerCase();
    const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'].includes(ext);
    const isVideo = ['mp4', 'webm', 'mov'].includes(ext);
    const isAudio = ['mp3', 'wav', 'ogg'].includes(ext);

    if (isImage) return `<img src="${url}" alt="预览" loading="lazy">`;
    if (isVideo) return `<video src="${url}" controls preload="metadata"></video>`;
    if (isAudio) return `<audio src="${url}" controls preload="metadata"></audio>`;
    return `<div class="file-icon">📄</div>`;
}


// --- HTML 页面生成函数 ---

/**
 * 生成登录页面 HTML
 */
function generateLoginPage() {
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>用户登录</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f2f5; }
        .login-container { background: #fff; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 360px; }
        h1 { text-align: center; color: #333; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #555; }
        input { width: 100%; padding: 0.75rem; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 0.75rem; border: none; border-radius: 4px; background-color: #007bff; color: white; font-size: 1rem; cursor: pointer; transition: background-color 0.3s; }
        button:hover { background-color: #0056b3; }
        .error-message { color: red; text-align: center; margin-top: 1rem; display: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>登录</h1>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">密码</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">登录</button>
        </form>
        <p id="errorMessage" class="error-message"></p>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorMessage = document.getElementById('errorMessage');
            
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            if (response.ok) {
                window.location.href = '/upload';
            } else {
                const data = await response.json();
                errorMessage.textContent = data.message || '登录失败';
                errorMessage.style.display = 'block';
            }
        });
    </script>
</body>
</html>`;
}

/**
 * 生成文件上传页面 HTML
 */
function generateUploadPage() {
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件上传</title>
    <style>
        :root { --primary-color: #007bff; --bg-color: #f8f9fa; --card-bg: #fff; --text-color: #333; --border-color: #dee2e6; }
        body { font-family: sans-serif; background-color: var(--bg-color); color: var(--text-color); margin: 0; padding: 1rem; }
        .container { max-width: 800px; margin: 0 auto; }
        nav { display: flex; justify-content: center; gap: 1rem; margin-bottom: 2rem; }
        nav a { text-decoration: none; color: var(--primary-color); font-weight: 500; padding: 0.5rem 1rem; border-radius: 5px; transition: background-color 0.2s; }
        nav a:hover, nav a.active { background-color: rgba(0, 123, 255, 0.1); }
        .card { background-color: var(--card-bg); border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); padding: 2rem; }
        .upload-area { border: 2px dashed var(--border-color); border-radius: 8px; padding: 2rem; text-align: center; cursor: pointer; transition: background-color 0.3s, border-color 0.3s; }
        .upload-area.dragover { background-color: #e9ecef; border-color: var(--primary-color); }
        .upload-area p { margin: 0; font-size: 1.2rem; color: #6c757d; }
        #fileInput { display: none; }
        #progressBar { width: 100%; background-color: #e9ecef; border-radius: 4px; overflow: hidden; height: 10px; margin-top: 1rem; display: none; }
        #progress { width: 0%; height: 100%; background-color: var(--primary-color); transition: width 0.4s; }
        .result { margin-top: 1.5rem; display: none; }
        .result input { width: 100%; padding: 0.5rem; border: 1px solid var(--border-color); border-radius: 4px; margin-bottom: 0.5rem; box-sizing: border-box; }
        .result button { padding: 0.5rem 1rem; border: none; border-radius: 4px; background-color: #28a745; color: white; cursor: pointer; }
        footer { text-align: center; margin-top: 2rem; color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <a href="/upload" class="active">上传文件</a>
            <a href="/admin">管理文件</a>
        </nav>
        <div class="card">
            <div id="uploadArea" class="upload-area">
                <p>点击或拖拽文件到此处上传</p>
                <small id="uploadHint"></small>
            </div>
            <input type="file" id="fileInput">
            <div id="progressBar"><div id="progress"></div></div>
            <div id="result" class="result">
                <p id="status"></p>
                <input type="text" id="fileUrl" readonly>
                <button onclick="copyUrl()">复制链接</button>
            </div>
        </div>
        <footer>
            <p>Powered by <a href="https://github.com/yutian81/CF-tgfile" target="_blank">CF-tgfile</a></p>
        </footer>
    </div>
    <script>
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const progressBar = document.getElementById('progressBar');
        const progress = document.getElementById('progress');
        const resultDiv = document.getElementById('result');
        const statusP = document.getElementById('status');
        const fileUrlInput = document.getElementById('fileUrl');
        const uploadHint = document.getElementById('uploadHint');
        let MAX_SIZE_MB = 20;

        fetch('/config').then(res => res.json()).then(config => {
            MAX_SIZE_MB = config.maxSizeMB;
            uploadHint.textContent = \`最大文件大小: \${MAX_SIZE_MB}MB\`;
        });

        uploadArea.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                handleFileUpload(fileInput.files[0]);
            }
        });

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadArea.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        uploadArea.addEventListener('dragenter', () => uploadArea.classList.add('dragover'));
        uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('dragover'));
        uploadArea.addEventListener('drop', (e) => {
            uploadArea.classList.remove('dragover');
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                handleFileUpload(files[0]);
            }
        });

        function handleFileUpload(file) {
            if (file.size > MAX_SIZE_MB * 1024 * 1024) {
                showResult(\`✘ 文件大小超过 \${MAX_SIZE_MB}MB 限制\`, '', 'error');
                return;
            }

            const formData = new FormData();
            formData.append('file', file);

            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/upload', true);

            xhr.upload.onprogress = (event) => {
                if (event.lengthComputable) {
                    const percentComplete = (event.loaded / event.total) * 100;
                    progressBar.style.display = 'block';
                    progress.style.width = percentComplete + '%';
                }
            };

            xhr.onload = () => {
                progress.style.width = '100%';
                setTimeout(() => { progressBar.style.display = 'none'; progress.style.width = '0%'; }, 500);
                
                try {
                    const response = JSON.parse(xhr.responseText);
                    if (response.status === 1) {
                        showResult(response.msg, response.url, 'success');
                    } else {
                        showResult(response.msg || '上传失败', response.error || '', 'error');
                    }
                } catch (e) {
                    showResult('✘ 上传失败', '服务器返回无效响应', 'error');
                }
            };

            xhr.onerror = () => {
                showResult('✘ 上传失败', '网络错误或服务器无响应', 'error');
                 progressBar.style.display = 'none';
            };
            
            showResult('上传中...', '', 'info');
            xhr.send(formData);
        }

        function showResult(message, url, type) {
            resultDiv.style.display = 'block';
            statusP.textContent = message;
            statusP.style.color = type === 'error' ? 'red' : (type === 'success' ? 'green' : 'black');
            fileUrlInput.value = url;
            fileUrlInput.style.display = url ? 'block' : 'none';
            fileUrlInput.nextElementSibling.style.display = url ? 'inline-block' : 'none';
        }

        function copyUrl() {
            fileUrlInput.select();
            document.execCommand('copy');
            alert('链接已复制到剪贴板');
        }
    </script>
</body>
</html>`;
}

/**
 * 生成文件管理页面 HTML
 * @param {Array} fileList - 文件对象数组
 * @param {object} stats - 统计数据对象
 */
function generateAdminPage(fileList, stats) {
    const fileCards = fileList.map(file => `
        <div class="file-card" data-url="${file.url}">
            <div class="file-checkbox-container">
                <input type="checkbox" class="file-checkbox" value="${file.url}">
            </div>
            <div class="file-preview">${getPreviewHtml(file.url)}</div>
            <div class="file-info">
                <div class="file-name" title="${file.file_name}">${file.file_name}</div>
                <div class="file-meta">
                    <span>${formatSize(file.file_size || 0)}</span> | 
                    <span>${new Date(file.created_at).toLocaleString()}</span>
                </div>
            </div>
            <div class="file-actions">
                <button class="btn btn-share" onclick="showQRCode('${file.url}')">分享</button>
                <a class="btn btn-download" href="${file.url}?download=true" download="${file.file_name}">下载</a>
                <button class="btn btn-delete" onclick="deleteFile(this, '${file.url}')">删除</button>
            </div>
        </div>
    `).join('');

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件管理</title>
    <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
    <style>
        :root { --primary-color: #007bff; --bg-color: #f8f9fa; --card-bg: #fff; --text-color: #333; --border-color: #dee2e6; --danger-color: #dc3545; }
        body { font-family: sans-serif; background-color: var(--bg-color); color: var(--text-color); margin: 0; padding: 1rem; }
        .container { max-width: 1200px; margin: 0 auto; }
        nav { display: flex; justify-content: center; gap: 1rem; margin-bottom: 1.5rem; }
        nav a { text-decoration: none; color: var(--primary-color); font-weight: 500; padding: 0.5rem 1rem; border-radius: 5px; transition: background-color 0.2s; }
        nav a:hover, nav a.active { background-color: rgba(0, 123, 255, 0.1); }
        
        .toolbar { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; background-color: var(--card-bg); padding: 1rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 1.5rem; }
        .stats { display: flex; gap: 1.5rem; font-size: 0.9rem; color: #6c757d; }
        .actions-group { display: flex; align-items: center; gap: 1rem; }
        .actions-group label { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; }
        .search-box { display: flex; }
        .search-box input { border: 1px solid var(--border-color); border-right: none; padding: 0.5rem; border-radius: 4px 0 0 4px; }
        .search-box button { border: 1px solid var(--primary-color); background-color: var(--primary-color); color: white; padding: 0.5rem 1rem; border-radius: 0 4px 4px 0; cursor: pointer; }
        
        .file-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1.5rem; }
        .file-card { background-color: var(--card-bg); border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); display: flex; flex-direction: column; overflow: hidden; transition: transform 0.2s, box-shadow 0.2s; position: relative; }
        .file-card:hover { transform: translateY(-5px); box-shadow: 0 4px 12px rgba(0,0,0,0.12); }
        .file-checkbox-container { position: absolute; top: 10px; left: 10px; z-index: 10; }
        .file-checkbox { transform: scale(1.5); }
        .file-preview { width: 100%; height: 180px; background-color: #f0f2f5; display: flex; justify-content: center; align-items: center; overflow: hidden; }
        .file-preview img, .file-preview video { width: 100%; height: 100%; object-fit: cover; }
        .file-preview .file-icon { font-size: 4rem; color: #adb5bd; }
        .file-info { padding: 1rem; flex-grow: 1; }
        .file-name { font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .file-meta { font-size: 0.8rem; color: #6c757d; margin-top: 0.5rem; }
        .file-actions { display: flex; border-top: 1px solid var(--border-color); }
        .btn { flex: 1; padding: 0.75rem; text-align: center; background: none; border: none; cursor: pointer; transition: background-color 0.2s; font-size: 0.9rem; text-decoration: none; color: var(--text-color); }
        .btn:not(:last-child) { border-right: 1px solid var(--border-color); }
        .btn:hover { background-color: #f8f9fa; }
        .btn-delete:hover { background-color: #fff0f1; color: var(--danger-color); }
        .btn-delete-selected { background-color: var(--danger-color); color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; }
        
        .qr-modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); justify-content: center; align-items: center; }
        .qr-content { background-color: white; padding: 2rem; border-radius: 8px; text-align: center; }
        #qrcode { margin-bottom: 1.5rem; }
        .qr-buttons button { margin: 0 0.5rem; padding: 0.5rem 1.5rem; border-radius: 4px; cursor: pointer; }
        .qr-copy { background-color: var(--primary-color); color: white; border: none; }
        .qr-close { background-color: #6c757d; color: white; border: none; }
        
        .toast { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background-color: #333; color: white; padding: 10px 20px; border-radius: 5px; z-index: 2000; opacity: 0; transition: opacity 0.5s; }
        .toast.show { opacity: 1; }
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <a href="/upload">上传文件</a>
            <a href="/admin" class="active">管理文件</a>
        </nav>

        <div class="toolbar">
            <div class="stats">
                <span>总文件: <strong>${stats.total_files || 0}</strong></span>
                <span>总大小: <strong>${formatSize(stats.total_size || 0)}</strong></span>
            </div>
            <div class="actions-group">
                <label><input type="checkbox" id="selectAllCheckbox"> 全选</label>
                <button id="deleteSelectedButton" class="btn-delete-selected">删除选中</button>
            </div>
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="搜索文件名...">
                <button id="searchButton">搜索</button>
            </div>
        </div>

        <div class="file-grid" id="fileGrid">
            ${fileCards}
        </div>
    </div>

    <div id="qrModal" class="qr-modal">
        <div class="qr-content">
            <div id="qrcode"></div>
            <input type="text" id="qrUrlInput" style="position:absolute;left:-9999px;">
            <div class="qr-buttons">
                <button class="qr-copy" onclick="handleCopyUrl()">复制链接</button>
                <button class="qr-close" onclick="closeQRModal()">关闭</button>
            </div>
        </div>
    </div>
    
    <div id="toast" class="toast"></div>

    <script>
        let currentUrlForQR = '';

        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.classList.add('show');
            setTimeout(() => { toast.classList.remove('show'); }, 3000);
        }

        function showQRCode(url) {
            currentUrlForQR = url;
            const modal = document.getElementById('qrModal');
            const qrcodeContainer = document.getElementById('qrcode');
            qrcodeContainer.innerHTML = '';
            new QRCode(qrcodeContainer, {
                text: url,
                width: 200,
                height: 200,
            });
            modal.style.display = 'flex';
        }

        function closeQRModal() {
            document.getElementById('qrModal').style.display = 'none';
        }

        function handleCopyUrl() {
            const input = document.getElementById('qrUrlInput');
            input.value = currentUrlForQR;
            input.select();
            document.execCommand('copy');
            showToast('链接已复制');
            closeQRModal();
        }

        async function deleteFile(button, url) {
            if (!confirm('确定要删除这个文件吗？文件将从 Telegram 和数据库中永久移除。')) return;

            button.disabled = true;
            button.textContent = '删除中...';

            try {
                const response = await fetch('/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                const result = await response.json();
                if (result.success) {
                    showToast('文件删除成功');
                    button.closest('.file-card').remove();
                } else {
                    throw new Error(result.message);
                }
            } catch (error) {
                showToast('删除失败: ' + error.message);
                button.disabled = false;
                button.textContent = '删除';
            }
        }
        
        // 全选/取消全选
        const selectAllCheckbox = document.getElementById('selectAllCheckbox');
        const fileCheckboxes = document.querySelectorAll('.file-checkbox');
        selectAllCheckbox.addEventListener('change', (e) => {
            fileCheckboxes.forEach(checkbox => {
                checkbox.checked = e.target.checked;
            });
        });

        // 批量删除
        const deleteSelectedButton = document.getElementById('deleteSelectedButton');
        deleteSelectedButton.addEventListener('click', async () => {
            const selectedUrls = Array.from(fileCheckboxes)
                .filter(cb => cb.checked)
                .map(cb => cb.value);

            if (selectedUrls.length === 0) {
                showToast('请先选择要删除的文件');
                return;
            }

            if (!confirm(\`确定要删除选中的 \${selectedUrls.length} 个文件吗？此操作不可恢复。\`)) return;
            
            deleteSelectedButton.disabled = true;
            deleteSelectedButton.textContent = '删除中...';

            try {
                const response = await fetch('/delete-bulk', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ urls: selectedUrls })
                });
                const result = await response.json();
                showToast(result.message);
                if (result.success) {
                    // 重新加载页面以显示最新列表
                    window.location.reload();
                }
            } catch (error) {
                showToast('批量删除时发生错误: ' + error.message);
            } finally {
                deleteSelectedButton.disabled = false;
                deleteSelectedButton.textContent = '删除选中';
            }
        });

        // 搜索功能
        const searchButton = document.getElementById('searchButton');
        const searchInput = document.getElementById('searchInput');
        
        const performSearch = async () => {
            const query = searchInput.value.trim();
            if (!query) {
                window.location.reload(); // 如果搜索框为空，则刷新页面显示所有
                return;
            }
            try {
                const response = await fetch('/search', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query })
                });
                const result = await response.json();
                if (result.files) {
                    updateFileGrid(result.files);
                } else {
                    throw new Error(result.error || '搜索失败');
                }
            } catch (error) {
                showToast('搜索失败: ' + error.message);
            }
        };

        searchButton.addEventListener('click', performSearch);
        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                performSearch();
            }
        });

        function updateFileGrid(files) {
            const fileGrid = document.getElementById('fileGrid');
            if (files.length === 0) {
                fileGrid.innerHTML = '<p>未找到匹配的文件。</p>';
                return;
            }
            const newCards = files.map(file => \`
                <div class="file-card" data-url="\${file.url}">
                    <div class="file-checkbox-container">
                        <input type="checkbox" class="file-checkbox" value="\${file.url}">
                    </div>
                    <div class="file-preview">\${getPreviewHtml(file.url)}</div>
                    <div class="file-info">
                        <div class="file-name" title="\${file.file_name}">\${file.file_name}</div>
                        <div class="file-meta">
                            <span>\${formatSize(file.file_size || 0)}</span> | 
                            <span>\${new Date(file.created_at).toLocaleString()}</span>
                        </div>
                    </div>
                    <div class="file-actions">
                        <button class="btn btn-share" onclick="showQRCode('\${file.url}')">分享</button>
                        <a class="btn btn-download" href="\${file.url}?download=true" download="\${file.file_name}">下载</a>
                        <button class="btn btn-delete" onclick="deleteFile(this, '\${file.url}')">删除</button>
                    </div>
                </div>
            \`).join('');
            fileGrid.innerHTML = newCards;
            // 重新绑定事件
            const newSelectAll = document.getElementById('selectAllCheckbox');
            const newFileCheckboxes = document.querySelectorAll('.file-checkbox');
            newSelectAll.addEventListener('change', (e) => {
                newFileCheckboxes.forEach(checkbox => {
                    checkbox.checked = e.target.checked;
                });
            });
        }
        
        // 辅助函数，需要和Worker中的函数保持一致
        function formatSize(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            return \`\${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} \${units[i]}\`;
        }
        function getPreviewHtml(url) {
            const ext = (url.split('.').pop() || '').toLowerCase();
            const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'].includes(ext);
            if (isImage) return \`<img src="\${url}" alt="预览" loading="lazy">\`;
            return \`<div class="file-icon">📄</div>\`;
        }

    </script>
</body>
</html>`;
}
