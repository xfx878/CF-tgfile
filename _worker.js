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
      cookie: Number(env.COOKIE) || 7, // Cookie validity defaults to 7 days
      maxSizeMB: Number(env.MAX_SIZE_MB) || 20 // Max single file upload size defaults to 20M
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
      '/update-file': () => handleUpdateFileRequest(request, config),
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
  const authToken = cookies.match(/auth_token=([^;]+)/); // Get auth_token from cookie
  if (authToken) {
    try {
      // Decode token and verify expiration
      const tokenData = JSON.parse(atob(authToken[1]));
      const now = Date.now();           
      // Check if token has expired
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
    if (!fileId) throw new Error('Could not get file ID');
    if (!messageId) throw new Error('Could not get TG message ID');

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
    } else if (error.message.includes('Could not get file ID') || error.message.includes('Could not get TG message ID')) {
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

  const filesResult = await config.database.prepare(
    `SELECT url, fileId, message_id, created_at, file_name, file_size, mime_type, password
    FROM files
    ORDER BY created_at DESC`
  ).all();

  const fileList = filesResult.results || [];
  const totalFiles = fileList.length;

  const fileCards = fileList.map(file => {
    const fileName = file.file_name;
    const fileSize = formatSize(file.file_size || 0);
    const createdAt = new Date(file.created_at).toISOString().replace('T', ' ').split('.')[0];
    const passwordDisplay = file.password ? `<div class="file-password" title="Click to copy password" onclick="copyPassword('${file.password}', event)">Password: ****</div>` : '<div>No Password</div>';

    return `
      <div class="file-card" data-url="${file.url}">
        <input type="checkbox" class="file-checkbox">
        <div class="file-preview">
          ${getPreviewHtml(file.url)}
        </div>
        <div class="file-info">
          <div class="file-name" title="${fileName}">${fileName}</div>
          <div>${fileSize}</div>
          <div>${createdAt}</div>
          ${passwordDisplay}
        </div>
        <div class="file-actions">
          <button class="btn btn-share" onclick="showQRCode('${file.url}')">Share</button>
          <button class="btn btn-edit" onclick="openEditModal('${file.url}', '${fileName}', '${file.password || ''}')">Edit</button>
          <a class="btn btn-down" href="${file.url}" download="${fileName}">Download</a>
        </div>
      </div>
    `;
  }).join('');

  const qrModal = `
    <div id="qrModal" class="modal">
      <div class="modal-content">
        <span class="close-btn" onclick="closeModal('qrModal')">&times;</span>
        <h2>Share File</h2>
        <div id="qrcode"></div>
        <div class="share-link-container">
            <a id="shareLink" href="#" target="_blank"></a>
            <button id="copyShareLink" class="btn btn-copy" onclick="handleCopyUrl()">Copy</button>
        </div>
      </div>
    </div>
  `;
  
  const editModal = `
    <div id="editModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeModal('editModal')">&times;</span>
            <h2>Edit File Info</h2>
            <form id="editForm">
                <input type="hidden" id="editFileUrl">
                <div class="form-group">
                    <label for="editFileName">File Name:</label>
                    <input type="text" id="editFileName" required>
                </div>
                <div class="form-group">
                    <label for="editFilePassword">Password (leave blank for no password):</label>
                    <input type="text" id="editFilePassword">
                </div>
                <button type="submit" class="btn">Save Changes</button>
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
       WHERE file_name LIKE ?
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
    return `<img src="${url}" alt="Preview" loading="lazy">`;
  } else if (isVideo) {
    return `<video src="${url}" controls muted loop preload="metadata"></video>`;
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
    const file = await config.database.prepare(
      `SELECT fileId, message_id, file_name, mime_type, password
      FROM files WHERE url = ?`
    ).bind(url.origin + url.pathname).first();

    if (!file) {
      return new Response('File not found', { 
        status: 404,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }

    // Handle password protection
    if (file.password) {
        if (request.method === 'POST') {
            const formData = await request.formData();
            const submittedPassword = formData.get('password');
            if (submittedPassword === file.password) {
                // Correct password, serve file and set a temporary access cookie
                const response = await serveFile(file, config, cache, cacheKey);
                const expiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes access
                response.headers.append('Set-Cookie', `access_${file.fileId}=true; Path=${url.pathname}; Expires=${expiry.toUTCString()}; HttpOnly; Secure`);
                return response;
            } else {
                // Incorrect password
                return new Response(generatePasswordPromptPage(url.pathname, true), { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
            }
        }
        
        const cookie = request.headers.get('Cookie') || '';
        if (!cookie.includes(`access_${file.fileId}=true`)) {
            // No access cookie, show password prompt
            return new Response(generatePasswordPromptPage(url.pathname), { status: 200, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }
    }


    // Check cache for non-password protected files or if access is granted
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      console.log(`[Cache Hit] ${url.toString()}`);
      return cachedResponse;
    }

    return await serveFile(file, config, cache, cacheKey);

  } catch (error) {
    console.error(`[Error] ${error.message} for ${url.toString()}`);
    return new Response('Internal server error', { 
      status: 500,
      headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
    });
  }
}

async function serveFile(file, config, cache, cacheKey) {
     // Get Telegram file path
    const tgResponse = await fetch(
      `https://api.telegram.org/bot${config.tgBotToken}/getFile?file_id=${file.fileId}`
    );

    if (!tgResponse.ok) {
      console.error(`[Telegram API Error] ${await tgResponse.text()} for file ${file.fileId}`);
      return new Response('Failed to get file', { 
        status: 500,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }

    const tgData = await tgResponse.json();
    const filePath = tgData.result?.file_path;

    if (!filePath) {
      console.error(`[Invalid Path] No file_path in response for ${file.fileId}`);
      return new Response('Invalid file path', { 
        status: 404,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }

    // Download file
    const fileUrl = `https://api.telegram.org/file/bot${config.tgBotToken}/${filePath}`;
    const fileResponse = await fetch(fileUrl);

    if (!fileResponse.ok) {
      console.error(`[Download Error] Failed to download from ${fileUrl}`);
      return new Response('Failed to download file', { 
        status: 500,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }

    const contentType = file.mime_type || getContentType(file.file_name.split('.').pop().toLowerCase());

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
    console.log(`[Cache Set] ${cacheKey.url}`);
    return response;
}

// Handle file deletion
async function handleDeleteRequest(request, config) {
  if (config.enableAuth && !authenticate(request, config)) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' }});
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
        
        if (!file) {
          results.push({ url, success: false, message: 'File not found' });
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
             results.push({ url, success: true, message: `DB record deleted, but TG message deletion failed: ${deleteError}` });
        } else {
             results.push({ url, success: true, message: 'File deleted successfully' });
        }
    }
    
    return new Response(JSON.stringify({ results }), { headers: { 'Content-Type': 'application/json' }});

  } catch (error) {
    console.error(`[Delete Error] ${error.message}`);
    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { 'Content-Type': 'application/json' }});
  }
}

// Handle file info update
async function handleUpdateFileRequest(request, config) {
    if (config.enableAuth && !authenticate(request, config)) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }

    try {
        const { url, fileName, password } = await request.json();
        if (!url || !fileName) {
            return new Response(JSON.stringify({ error: 'Missing required fields' }), { status: 400 });
        }

        const result = await config.database.prepare(
            'UPDATE files SET file_name = ?, password = ? WHERE url = ?'
        ).bind(fileName, password || null, url).run();

        if (result.changes > 0) {
            return new Response(JSON.stringify({ success: true, message: 'File updated successfully' }), { headers: { 'Content-Type': 'application/json' } });
        } else {
            return new Response(JSON.stringify({ error: 'File not found or no changes made' }), { status: 404 });
        }

    } catch (error) {
        console.error(`[Update Error] ${error.message}`);
        return new Response(JSON.stringify({ error: 'Failed to update file' }), { status: 500 });
    }
}


// Supported upload file types
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
  return types[ext] || 'application/octet-stream';
}

async function handleBingImagesRequest() {
  const cache = caches.default;
  const cacheKey = new Request('https://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=8');
  
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
        'Cache-Control': 'public, max-age=21600', // Cache for 6 hours
        'Access-Control-Allow-Origin': '*' 
      }
    });
    
    await cache.put(cacheKey, response.clone());
    return response;
  } catch (error) {
    console.error('Error during Bing API request:', error);
    return new Response('Failed to request Bing API', { status: 500 });
  }
}

// File size calculation function
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${parseFloat((bytes / Math.pow(1024, i)).toFixed(2))} ${units[i]}`;
}

// Generate login page /login
function generateLoginPage() {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
      body { display: flex; justify-content: center; align-items: center; height: 100vh; background-size: cover; background-position: center; font-family: Arial, sans-serif; transition: background-image 1s ease-in-out; }
      .login-container { background: rgba(255, 255, 255, 0.8); padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); width: 100%; max-width: 400px; backdrop-filter: blur(10px); }
      .form-group { margin-bottom: 1.5rem; }
      input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; box-sizing: border-box; }
      button { width: 100%; padding: 0.75rem; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
      button:hover { background: #0056b3; }
      .error { color: #dc3545; margin-top: 1rem; display: none; text-align: center; }
    </style>
  </head>
  <body>
    <div class="login-container">
      <h2 style="text-align: center; margin-bottom: 2rem;">Login</h2>
      <form id="loginForm">
        <div class="form-group"><input type="text" id="username" placeholder="Username" required></div>
        <div class="form-group"><input type="password" id="password" placeholder="Password" required></div>
        <button type="submit">Login</button>
        <div id="error" class="error">Incorrect username or password</div>
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
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload</title>
    <style>
      body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-size: cover; background-position: center; margin: 0; transition: background-image 1s ease-in-out; }
      .container { max-width: 800px; width: 90%; background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 20px 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); overflow-y: auto; max-height: 90vh; }
      .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
      .upload-area { border: 2px dashed #007bff; padding: 40px; text-align: center; border-radius: 8px; cursor: pointer; transition: all 0.3s; }
      .upload-area.dragover { border-color: #0056b3; background: rgba(0, 123, 255, 0.1); }
      .password-section { margin-top: 15px; }
      .password-section input { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
      .preview-area { margin-top: 20px; }
      .preview-item { display: flex; align-items: center; padding: 10px; border: 1px solid #ddd; margin-bottom: 10px; border-radius: 4px; }
      .preview-item img { max-width: 100px; max-height: 100px; margin-right: 10px; }
      .preview-item .info { flex-grow: 1; }
      .url-area { margin-top: 20px; }
      .url-area textarea { width: 100%; min-height: 100px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
      .admin-link { color: #007bff; text-decoration: none; }
      .admin-link:hover { text-decoration: underline; }
      .button-group { margin-top: 10px; display: flex; justify-content: space-between; align-items: center; }
      .button-container button { margin-right: 10px; padding: 8px 12px; border: none; border-radius: 4px; background: #007bff; color: white; cursor: pointer; }
      .button-container button:hover { background: #0056b3; }
      .progress-bar { height: 20px; background: #eee; border-radius: 10px; margin: 8px 0; overflow: hidden; position: relative; }
      .progress-track { height: 100%; background: #007bff; transition: width 0.3s ease; width: 0; }
      .progress-text { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); color: #333; font-size: 12px; mix-blend-mode: difference; filter: invert(1); }
      .success .progress-track { background: #28a745; }
      .error .progress-track { background: #dc3545; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header"><h1>File Upload</h1><a href="/admin" class="admin-link">Go to Management Page</a></div>
      <div class="upload-area" id="uploadArea">
        <p>Click to select or drag files here</p>
        <input type="file" id="fileInput" multiple style="display: none">
      </div>
      <div class="password-section">
        <input type="text" id="filePassword" placeholder="Set an access password for the file (optional)">
      </div>
      <div class="preview-area" id="previewArea"></div>
      <div class="url-area">
        <textarea id="urlArea" readonly placeholder="Uploaded links will appear here"></textarea>
        <div class="button-group">
          <div class="button-container">
            <button onclick="copyUrls('url')">Copy URL</button>
            <button onclick="copyUrls('markdown')">Copy Markdown</button>
            <button onclick="copyUrls('html')">Copy HTML</button>
          </div>
        </div>
      </div>
    </div>
    <script>
      async function setBingBackground() { /* same as login page */ 
          try { const response = await fetch('/bing'); const data = await response.json(); if (data.status && data.data.length > 0) { const randomIndex = Math.floor(Math.random() * data.data.length); document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`; } } catch (error) { console.error('Failed to get background image:', error); }
      }
      setBingBackground(); setInterval(setBingBackground, 3600000);

      const uploadArea = document.getElementById('uploadArea');
      const fileInput = document.getElementById('fileInput');
      const previewArea = document.getElementById('previewArea');
      const urlArea = document.getElementById('urlArea');
      const filePasswordInput = document.getElementById('filePassword');
      let uploadedUrls = [];

      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(e => { uploadArea.addEventListener(e, p, false); document.body.addEventListener(e, p, false); });
      function p(e) { e.preventDefault(); e.stopPropagation(); }
      ['dragenter', 'dragover'].forEach(e => uploadArea.addEventListener(e, () => uploadArea.classList.add('dragover'), false));
      ['dragleave', 'drop'].forEach(e => uploadArea.addEventListener(e, () => uploadArea.classList.remove('dragover'), false));

      uploadArea.addEventListener('drop', e => handleFiles({ target: { files: e.dataTransfer.files } }), false);
      uploadArea.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', handleFiles);

      document.addEventListener('paste', async e => { for (let item of (e.clipboardData || e.originalEvent.clipboardData).items) { if (item.kind === 'file') { await uploadFile(item.getAsFile()); } } });

      async function handleFiles(e) {
        const response = await fetch('/config');
        const config = await response.json();
        for (let file of Array.from(e.target.files)) {
          if (file.size > config.maxSizeMB * 1024 * 1024) {
            alert(\`File exceeds \${config.maxSizeMB}MB limit\`);
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
            progressText.textContent = '✗ Response parsing failed';
            preview.classList.add('error');
          }
        });

        const formData = new FormData();
        formData.append('file', file);
        formData.append('password', filePasswordInput.value);
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
        info.innerHTML = \`<div>\${file.name}</div><div>\${formatSize(file.size)}</div><div class="progress-bar"><div class="progress-track"></div><span class="progress-text">0%</span></div>\`;
        div.appendChild(info);
        return div;
      }

      function formatSize(bytes) { const u = ['B', 'KB', 'MB', 'GB']; let s = bytes, i = 0; while (s >= 1024 && i < u.length - 1) { s /= 1024; i++; } return \`\${s.toFixed(2)} \${u[i]}\`; }
      function updateUrlArea() { urlArea.value = uploadedUrls.join('\\n'); }
      function copyUrls(format) {
        let text;
        switch (format) {
          case 'markdown': text = uploadedUrls.map(url => \`![](\${url})\`).join('\\n'); break;
          case 'html': text = uploadedUrls.map(url => \`<img src="\${url}">\`).join('\\n'); break;
          default: text = uploadedUrls.join('\\n');
        }
        navigator.clipboard.writeText(text).then(() => alert('Copied to clipboard'));
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
    <title>File Management</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-size: cover; background-position: center; background-attachment: fixed; transition: background-image 1s ease-in-out; }
      .container { max-width: 1400px; margin: 0 auto; }
      .header { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); padding: 20px 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }
      .header h2 { margin: 0; }
      .header-controls { display: flex; gap: 15px; align-items: center; }
      .file-stats { font-size: 1.5em; font-weight: bold; color: red; }
      .search { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 250px; }
      .btn { padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; background: #007bff; color: white; text-decoration: none; display: inline-block; }
      .btn-danger { background: #dc3545; }
      .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 20px; }
      .file-card { background: rgba(255, 255, 255, 0.8); border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; position: relative; display: flex; flex-direction: column; }
      .file-preview { height: 150px; display: flex; align-items: center; justify-content: center; background: #f0f0f0; }
      .file-preview img, .file-preview video { max-width: 100%; max-height: 100%; object-fit: contain; }
      .file-info { padding: 10px; font-size: 14px; flex-grow: 1; }
      .file-name { font-weight: bold; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .file-password { cursor: pointer; color: #6c757d; }
      .file-actions { padding: 10px; border-top: 1px solid #eee; display: grid; grid-template-columns: repeat(3, 1fr); gap: 5px; }
      .file-actions .btn, .file-actions .btn-down { width: 100%; text-align: center; font-size: 12px; padding: 5px; box-sizing: border-box; }
      .file-checkbox { position: absolute; left: 10px; top: 10px; z-index: 10; transform: scale(1.5); }
      .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.6); justify-content: center; align-items: center; }
      .modal-content { background-color: #fefefe; margin: auto; padding: 20px; border: 1px solid #888; width: 90%; max-width: 500px; border-radius: 10px; position: relative; }
      .close-btn { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
      #qrcode { margin: 20px auto; }
      .share-link-container { display: flex; align-items: center; gap: 10px; margin-top: 15px; }
      .share-link-container a { flex-grow: 1; text-decoration: none; color: #007bff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      #editForm .form-group { margin-bottom: 15px; }
      #editForm label { display: block; margin-bottom: 5px; }
      #editForm input { width: 100%; padding: 8px; box-sizing: border-box; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h2>File Management</h2>
        <div class="header-controls">
          <span class="file-stats">Total: ${totalFiles}</span>
          <input type="text" class="search" placeholder="Search files..." id="searchInput">
          <button class="btn" id="selectAllBtn">Select All</button>
          <button class="btn btn-danger" id="deleteSelectedBtn">Delete Selected</button>
          <a href="/upload" class="btn">Back to Upload</a>
        </div>
      </div>
      <div class="grid" id="fileGrid">${fileCards}</div>
      ${qrModal}
      ${editModal}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/qrcodejs/qrcode.min.js"></script>
    <script>
      async function setBingBackground() { /* same as login page */ 
          try { const response = await fetch('/bing'); const data = await response.json(); if (data.status && data.data.length > 0) { const randomIndex = Math.floor(Math.random() * data.data.length); document.body.style.backgroundImage = \`url(\${data.data[randomIndex].url})\`; } } catch (error) { console.error('Failed to get background image:', error); }
      }
      setBingBackground(); setInterval(setBingBackground, 3600000);

      const searchInput = document.getElementById('searchInput');
      const fileGrid = document.getElementById('fileGrid');
      const fileCards = () => Array.from(fileGrid.children);

      searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        fileCards().forEach(card => {
          const fileName = card.querySelector('.file-name').textContent.toLowerCase();
          card.style.display = fileName.includes(searchTerm) ? '' : 'none';
        });
      });

      document.getElementById('selectAllBtn').addEventListener('click', () => {
        const checkboxes = document.querySelectorAll('.file-checkbox');
        const allChecked = Array.from(checkboxes).every(cb => cb.checked);
        checkboxes.forEach(cb => cb.checked = !allChecked);
      });

      document.getElementById('deleteSelectedBtn').addEventListener('click', async () => {
        const selectedUrls = Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => cb.closest('.file-card').dataset.url);
        if (selectedUrls.length === 0) {
            alert('Please select files to delete.');
            return;
        }
        if (confirm(`Are you sure you want to delete ${selectedUrls.length} selected file(s)?`)) {
            await deleteFiles(selectedUrls);
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
              if (!response.ok) throw new Error(result.error || 'Deletion failed');
              
              result.results.forEach(res => {
                  if (res.success) {
                      const card = document.querySelector(\`[data-url="\${res.url}"]\`);
                      if (card) card.remove();
                  }
              });
              alert('Deletion process completed.');
              // Update file count
              document.querySelector('.file-stats').textContent = `Total: ${document.querySelectorAll('.file-card').length}`;
          } catch (error) {
              alert('File deletion failed: ' + error.message);
          }
      }

      let currentShareUrl = '';
      function showQRCode(url) {
        currentShareUrl = url;
        const modal = document.getElementById('qrModal');
        const qrcodeDiv = document.getElementById('qrcode');
        const shareLink = document.getElementById('shareLink');
        shareLink.href = url;
        shareLink.textContent = url;
        qrcodeDiv.innerHTML = '';
        new QRCode(qrcodeDiv, { text: url, width: 200, height: 200 });
        modal.style.display = 'flex';
      }

      function handleCopyUrl() {
        navigator.clipboard.writeText(currentShareUrl).then(() => {
            const copyBtn = document.getElementById('copyShareLink');
            copyBtn.textContent = '✔ Copied';
            setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000);
        });
      }
      
      function copyPassword(password, event) {
        event.stopPropagation();
        navigator.clipboard.writeText(password).then(() => {
            alert('Password copied to clipboard');
        });
      }

      function closeModal(modalId) { document.getElementById(modalId).style.display = 'none'; }
      window.onclick = function(event) {
        if (event.target.classList.contains('modal')) {
          event.target.style.display = 'none';
        }
      }
      
      function openEditModal(url, name, password) {
        document.getElementById('editFileUrl').value = url;
        document.getElementById('editFileName').value = name;
        document.getElementById('editFilePassword').value = password;
        document.getElementById('editModal').style.display = 'flex';
      }

      document.getElementById('editForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('editFileUrl').value;
        const fileName = document.getElementById('editFileName').value;
        const password = document.getElementById('editFilePassword').value;

        try {
            const response = await fetch('/update-file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, fileName, password })
            });
            const result = await response.json();
            if (!response.ok || !result.success) throw new Error(result.error || 'Update failed');
            
            alert('File updated successfully!');
            closeModal('editModal');
            // Optimistically update UI
            const card = document.querySelector(\`[data-url="\${url}"]\`);
            if(card) {
                card.querySelector('.file-name').textContent = fileName;
                card.querySelector('.file-name').title = fileName;
                const passDiv = card.querySelector('.file-password');
                if(password) {
                    if(passDiv) {
                        passDiv.onclick = (event) => copyPassword(password, event);
                    } else {
                        // This part is complex, a full reload is easier
                        location.reload();
                    }
                } else {
                     if(passDiv) passDiv.outerHTML = '<div>No Password</div>';
                }
            } else {
                location.reload(); // Fallback to reload
            }
        } catch (error) {
            alert('Error updating file: ' + error.message);
        }
      });
    </script>
  </body>
  </html>`;
}

function generatePasswordPromptPage(url, error = false) {
    return `<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Required</title>
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; font-family: sans-serif; }
            .prompt-container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
            input { padding: 10px; margin-top: 10px; border: 1px solid #ccc; border-radius: 4px; width: 250px; }
            button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin-top: 10px; }
            .error { color: red; margin-top: 10px; ${error ? '' : 'display: none;'} }
        </style>
    </head>
    <body>
        <div class="prompt-container">
            <h2>This file is password protected</h2>
            <p>Please enter the password to access it.</p>
            <form method="POST" action="${url}">
                <input type="password" name="password" required>
                <br>
                <button type="submit">Submit</button>
            </form>
            <p class="error">Incorrect password. Please try again.</p>
        </div>
    </body>
    </html>`;
}
