// 通用的路径验证和节点名称提取函数
function validateSubscriptionPath(path) {
  return /^[a-z0-9-]{5,50}$/.test(path);
}

// 节点类型常量定义
const NODE_TYPES = {
  SS: 'ss://',
  VMESS: 'vmess://',
  TROJAN: 'trojan://',
  VLESS: 'vless://',
  SOCKS: 'socks://',
  HYSTERIA2: 'hysteria2://',
  TUIC: 'tuic://',
  SNELL: 'snell,'
};

function extractNodeName(nodeLink) {
  if (!nodeLink) return '未命名节点';
  
  // 处理snell节点
  if(nodeLink.includes(NODE_TYPES.SNELL)) {
    const name = nodeLink.split('=')[0].trim();
    return name || '未命名节点';
  }
  
  // 处理 VMess 链接
  if (nodeLink.toLowerCase().startsWith(NODE_TYPES.VMESS)) {
    try {
      const config = JSON.parse(safeBase64Decode(nodeLink.substring(8)));
      if (config.ps) {
        return safeUtf8Decode(config.ps);
      }
    } catch {}
    return '未命名节点';
  }

  // 处理其他使用哈希标记名称的链接类型（SS、TROJAN、VLESS、SOCKS、Hysteria2、TUIC等）
  const hashIndex = nodeLink.indexOf('#');
  if (hashIndex !== -1) {
    try {
      return decodeURIComponent(nodeLink.substring(hashIndex + 1));
    } catch {
      return nodeLink.substring(hashIndex + 1) || '未命名节点';
    }
  }
  return '未命名节点';
}

export default {
  async fetch(request, env) {
    // 解析请求路径和参数
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    // 检查是否有查询参数
    if (url.search && !pathname.startsWith('/admin')) {
      return new Response('Not Found', { status: 404 });
    }

    // 从环境变量获取配置路径，如果未设置则使用默认值
    const adminPath = env.ADMIN_PATH || 'admin';
    
    // 从环境变量获取登录凭据
    const adminUsername = env.ADMIN_USERNAME || 'admin';
    const adminPassword = env.ADMIN_PASSWORD || 'password';
    
    // 处理登录页面请求
    if (pathname === `/${adminPath}/login`) {
      if (method === "GET") {
        return serveLoginPage(adminPath);
      } else if (method === "POST") {
        return handleLogin(request, env, adminUsername, adminPassword, adminPath);
      }
    }
    
    // 处理登出请求
    if (pathname === `/${adminPath}/logout`) {
      return handleLogout(request, env, adminPath);
    }
    
    // 处理管理面板请求
    if (pathname === `/${adminPath}`) {
      const isAuthenticated = await verifySession(request, env);
      if (!isAuthenticated) {
        return Response.redirect(`${url.origin}/${adminPath}/login`, 302);
      }
      return serveAdminPanel(env, adminPath);
    }
    
    // 处理API请求
    if (pathname.startsWith(`/${adminPath}/api/`)) {
      // 验证会话
      const isAuthenticated = await verifySession(request, env);
      if (!isAuthenticated) {
        return new Response(JSON.stringify({
          success: false,
          message: '未授权访问'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 处理节点管理API请求
      const nodeApiMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)/nodes(?:/([^/]+|reorder))?$`));
      if (nodeApiMatch) {
        const subscriptionPath = nodeApiMatch[1];
        const nodeId = nodeApiMatch[2];
        
        try {
          // 更新节点顺序
          if (nodeId === 'reorder' && method === 'POST') {
            const { orders } = await request.json();
            
            if (!Array.isArray(orders) || orders.length === 0) {
              return new Response(JSON.stringify({
                success: false,
                message: '无效的排序数据'
              }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
              });
            }
            
            // 获取订阅ID
            const { results: subResults } = await env.DB.prepare(
              "SELECT id FROM subscriptions WHERE path = ?"
            ).bind(subscriptionPath).all();
            
            if (!subResults?.length) {
              return new Response(JSON.stringify({
                success: false,
                message: '订阅不存在'
              }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' }
              });
            }
            
            const subscriptionId = subResults[0].id;
            
            // 使用事务来确保数据一致性
            const statements = [];
            
            // 准备更新语句
            for (const { id, order } of orders) {
              statements.push(env.DB.prepare(
                "UPDATE nodes SET node_order = ? WHERE id = ? AND subscription_id = ?"
                              ).bind(order, id, subscriptionId));
            }
            
            // 执行批量更新
            const result = await env.DB.batch(statements);
            
            return new Response(JSON.stringify({
              success: true,
              message: '节点顺序已更新'
            }), {
              headers: { 'Content-Type': 'application/json' }
            });
          }
          
          // 获取节点列表
          if (!nodeId && method === 'GET') {
            return handleGetNodes(env, subscriptionPath);
          }
          
          // 创建新节点
          if (!nodeId && method === 'POST') {
            return handleCreateNode(request, env, subscriptionPath);
          }
          
          // 更新节点
          if (nodeId && nodeId !== 'reorder' && method === 'PUT') {
            return handleUpdateNode(request, env, subscriptionPath, nodeId);
          }
          
          // 删除节点
          if (nodeId && nodeId !== 'reorder' && method === 'DELETE') {
            return handleDeleteNode(env, subscriptionPath, nodeId);
          }
          
          return new Response(JSON.stringify({
            success: false,
            message: 'Method Not Allowed'
          }), {
            status: 405,
            headers: { 'Content-Type': 'application/json' }
          });
          
        } catch (error) {
          console.error('API请求处理失败:', error);
          return new Response(JSON.stringify({
            success: false,
            message: error.message || '服务器内部错误'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      }
      
      // 处理订阅管理API请求
      if (pathname.startsWith(`/${adminPath}/api/subscriptions`)) {
        // 获取单个订阅内容
        const getOneMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)$`));
        if (getOneMatch && method === 'GET') {
          return handleGetSubscription(env, getOneMatch[1]);
      }
      
      // 获取订阅列表
      if (pathname === `/${adminPath}/api/subscriptions` && method === 'GET') {
        return handleGetSubscriptions(env);
      }
      
      // 创建新订阅
      if (pathname === `/${adminPath}/api/subscriptions` && method === 'POST') {
          try {
            const { name, path } = await request.json();
            
            if (!name || !validateSubscriptionPath(path)) {
              return createErrorResponse('无效的参数', 400);
            }
            
            // 检查路径是否已存在
            const { results } = await env.DB.prepare(
              "SELECT COUNT(*) as count FROM subscriptions WHERE path = ?"
            ).bind(path).all();
            
            if (results[0].count > 0) {
              return createErrorResponse('该路径已被使用', 400);
            }
            
            // 创建订阅
            const result = await env.DB.prepare(
              "INSERT INTO subscriptions (name, path) VALUES (?, ?)"
                          ).bind(name, path).run();

            if (!result.success) {
              throw new Error('创建订阅失败');
            }

            return createSuccessResponse(null, '订阅创建成功');
          } catch (error) {
            console.error('创建订阅失败:', error);
            return createErrorResponse('创建订阅失败: ' + error.message);
          }
        }
        
        // 更新订阅信息
      const updateMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)$`));
      if (updateMatch && method === 'PUT') {
          const data = await request.json();
          return handleUpdateSubscriptionInfo(env, updateMatch[1], data);
      }
      
      // 删除订阅
      const deleteMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)$`));
      if (deleteMatch && method === 'DELETE') {
        return handleDeleteSubscription(env, deleteMatch[1]);
      }

        return new Response(JSON.stringify({
          success: false,
          message: 'Method Not Allowed'
        }), {
          status: 405,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return new Response(JSON.stringify({
        success: false,
        message: 'Not Found'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 处理订阅请求
    if (pathname.startsWith('/')) {
      // 检查路径格式是否合法（只允许一级或两级路径，如 /path 或 /path/surge 或 /path/v2ray 或 /path/clash）
      const pathParts = pathname.split('/').filter(Boolean);
      if (pathParts.length > 2) {
        return new Response('Not Found', { status: 404 });
      }
      
      if (pathParts.length === 2 && !['surge', 'v2ray', 'clash'].includes(pathParts[1])) {
        return new Response('Not Found', { status: 404 });
      }

      try {
        // 获取基本路径
        let basePath = pathname;
        if (pathname.endsWith('/surge')) {
          basePath = pathname.slice(1, -6);  // 移除开头的/和结尾的/surge
        } else if (pathname.endsWith('/v2ray')) {
          basePath = pathname.slice(1, -6);  // 移除开头的/和结尾的/v2ray
        } else if (pathname.endsWith('/clash')) {
          basePath = pathname.slice(1, -6);  // 移除开头的/和结尾的/clash
        } else {
          basePath = pathname.slice(1);      // 只移除开头的/
        }
        
        // 获取订阅信息
        const { results } = await env.DB.prepare(
          "SELECT * FROM subscriptions WHERE path = ?"
        ).bind(basePath).all();
        
        const subscription = results[0];
        
        if (subscription) {
          // 生成订阅内容
          const content = await generateSubscriptionContent(env, basePath);
          
          // 根据请求路径返回不同格式的内容
          if (pathname.endsWith('/surge')) {
            // 返回 Surge 格式
            const surgeContent = convertToSurge(content);
            return new Response(surgeContent, {
              headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            });
          } else if (pathname.endsWith('/v2ray')) {
            // 返回 Base64 编码格式，排除 snell 节点，包括 VLESS 节点
            const filteredContent = filterSnellNodes(content);
            const base64Content = safeBase64Encode(filteredContent);
            
            return new Response(base64Content, {
              headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            });
          } else if (pathname.endsWith('/clash')) {
            // 返回 Clash 格式
            const clashContent = convertToClash(content);
            return new Response(clashContent, {
              headers: { 'Content-Type': 'text/yaml; charset=utf-8' },
            });
          }
          
          // 返回普通订阅内容，排除 snell 节点
          const filteredContent = filterSnellNodes(content);
          return new Response(filteredContent, {
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
          });
        }
      } catch (error) {
        console.error('处理订阅请求失败:', error);
        return new Response('Internal Server Error', { status: 500 });
      }
      
      // 如果没有找到匹配的订阅，返回404
      return new Response('Not Found', { status: 404 });
    }
    
    // 其他所有路径返回 404
    return new Response('Not Found', { status: 404 });
  },
};

// 添加获取单个订阅的处理函数
async function handleGetSubscription(env, path) {
  try {
    const { results } = await env.DB.prepare(
      "SELECT * FROM subscriptions WHERE path = ?"
    ).bind(path).all();
    
    if (!results || results.length === 0) {
      return createErrorResponse('订阅不存在', 404);
    }
    
    return createSuccessResponse(results[0]);
  } catch (error) {
    console.error('获取订阅内容失败:', error);
    return createErrorResponse('获取订阅内容失败: ' + error.message);
  }
}

// 提供登录页面HTML
function serveLoginPage(adminPath) {
  const html = `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sub-Hub - 登录</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.0.0/css/all.min.css">
    <style>
      :root {
        --primary-color: #4e73df;
        --success-color: #1cc88a;
        --danger-color: #e74a3b;
        --transition-timing: 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        --box-shadow-light: 0 2px 10px rgba(0,0,0,0.05);
        --box-shadow-medium: 0 4px 15px rgba(0,0,0,0.08);
        --font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
        --text-color: #2d3748;
        --text-color-secondary: #444;
        --border-radius-sm: 8px;
        --border-radius-md: 12px;
        --border-radius-lg: 16px;
      }
      
      * {
        transition: all var(--transition-timing);
        font-family: var(--font-family);
      }
      
      html {
        scrollbar-gutter: stable;
      }
      
      
      /* 防止模态框打开时页面偏移 */
      .modal-open {
        padding-right: 0 !important;
      }

      /* 修复模态框背景遮罩的宽度 */
      .modal-backdrop {
        width: 100vw !important;
      }

      /* 优化模态框布局 */
      .modal-dialog {
        margin-right: auto !important;
        margin-left: auto !important;
        padding-right: 0 !important;
      }

      /* 标题和重要文字样式 */
      .navbar-brand,
      .subscription-name,
      .modal-title,
      .form-label {
        font-weight: 600;
        color: var(--text-color);
      }

      /* 按钮统一样式 */
      .btn,
      .logout-btn {
        font-weight: 500;
      }

      /* 次要文字样式 */
      .link-label,
      .form-text {
        color: var(--text-color-secondary);
      }

      /* 链接标签文字加粗 */
      .link-label small > span > span {
        font-weight: 600;
      }
      
      body {
        font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      
      .login-container {
        background-color: #fff;
        border-radius: 16px;
        box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        overflow: hidden;
        width: 360px;
        max-width: 90%;
      }
      
      .login-header {
        background: linear-gradient(120deg, var(--primary-color), #224abe);
        padding: 2rem 1.5rem;
        text-align: center;
        color: white;
      }
      
      .login-icon {
        background-color: white;
        color: var(--primary-color);
        width: 80px;
        height: 80px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 1rem;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
      }
      
      .login-icon i {
        font-size: 2.5rem;
      }
      
      .login-title {
        font-weight: 600;
        margin-bottom: 0.5rem;
      }
      
      .login-subtitle {
        opacity: 0.8;
        font-size: 0.9rem;
      }
      
      .login-form {
        padding: 2rem;
      }
      
      .form-floating {
        margin-bottom: 1.5rem;
      }
      
      .form-floating input {
        border-radius: 8px;
        height: 56px;
        border: 2px solid #e7eaf0;
        box-shadow: none;
      }
      
      .form-floating input:focus {
        border-color: var(--primary-color);
        box-shadow: 0 0 0 0.25rem rgba(78, 115, 223, 0.15);
      }
      
      .form-floating label {
        color: #7e7e7e;
        padding-left: 1rem;
      }
      
      .btn-login {
        background: linear-gradient(120deg, var(--primary-color), #224abe);
        border: none;
        border-radius: 8px;
        padding: 0.75rem 1.5rem;
        font-weight: 600;
        width: 100%;
        margin-top: 1rem;
        box-shadow: 0 4px 10px rgba(78, 115, 223, 0.35);
        transition: all 0.2s ease;
      }
      
      .btn-login:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 15px rgba(78, 115, 223, 0.4);
      }
      
      .alert {
        border-radius: 8px;
        font-size: 0.9rem;
        margin-bottom: 1.5rem;
        display: none;
      }

    </style>
  </head>
  <body>
    <div class="login-container">
      <div class="login-header">
        <div class="login-icon">
          <i class="fas fa-cube"></i>
        </div>
        <h3 class="login-title">Sub-Hub</h3>
        <p class="login-subtitle">请登录以继续使用</p>
      </div>
      
      <div class="login-form">
        <div class="alert alert-danger" id="loginAlert" role="alert">
          <i class="fas fa-exclamation-triangle me-2"></i>
          <span id="alertMessage">用户名或密码错误</span>
        </div>
        
        <form id="loginForm">
          <div class="form-floating">
            <input type="text" class="form-control" id="username" name="username" placeholder="用户名" required>
            <label for="username"><i class="fas fa-user me-2"></i>用户名</label>
          </div>
          
          <div class="form-floating">
            <input type="password" class="form-control" id="password" name="password" placeholder="密码" required>
            <label for="password"><i class="fas fa-lock me-2"></i>密码</label>
          </div>
          
          <button type="submit" class="btn btn-primary btn-login">
            <i class="fas fa-sign-in-alt me-2"></i>登录
          </button>
        </form>
      </div>
    </div>
    
    <script>
      document.getElementById('loginForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        try {
          const response = await fetch('/${adminPath}/login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
          });
          
          const data = await response.json();
          
          if (data.success) {
            // 登录成功，重定向到管理面板
            window.location.href = data.redirect;
          } else {
            // 显示错误消息
            document.getElementById('alertMessage').textContent = data.message;
            document.getElementById('loginAlert').style.display = 'block';
          }
        } catch (error) {
          // 显示错误消息
          document.getElementById('alertMessage').textContent = '登录请求失败，请重试';
          document.getElementById('loginAlert').style.display = 'block';
        }
      });
    </script>
  </body>
  </html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// 验证会话
async function verifySession(request, env) {
  const sessionId = getSessionFromCookie(request);
  if (!sessionId) return false;
  
  const now = Date.now();
  const { results } = await env.DB.prepare(`
    UPDATE sessions 
    SET expires_at = ? 
    WHERE session_id = ? AND expires_at > ?
    RETURNING *
  `).bind(now + 24 * 60 * 60 * 1000, sessionId, now).all();
  
  return results.length > 0;
}

// 从Cookie中获取会话ID
function getSessionFromCookie(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const sessionCookie = cookieHeader.split(';')
    .find(cookie => cookie.trim().startsWith('session='));
  return sessionCookie ? sessionCookie.trim().substring(8) : null;
}

// 生成安全的会话令牌
async function generateSecureSessionToken(username, env) {
  // 清理过期会话和用户旧会话
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now),
    env.DB.prepare("DELETE FROM sessions WHERE username = ?").bind(username)
  ]);

