# 5. 资源请求

客户端通过向资源服务器出示访问令牌来访问受保护资源。资源服务器必须验证访问令牌，并确保其未过期且其作用域覆盖了请求的资源。资源服务器用于验证访问令牌的方法超出本规范范围，但通常涉及资源服务器与授权服务器之间的交互或协调。例如，当资源服务器和授权服务器位于同一位置或属于同一系统时，它们可能共享数据库或其他存储；当两个组件独立运行时，它们可能使用令牌 Introspection [RFC7662] 或结构化访问令牌格式（如 JWT [RFC9068]）。

## 5.1. 持有者令牌请求

本节定义了在资源请求中向资源服务器发送持有者令牌的两种方法。客户端必须使用以下定义的两种方法之一，并且不得在每个请求中使用多种方法传输令牌。

特别重要的是，客户端不得在 URI 查询参数中发送访问令牌，资源服务器必须忽略 URI 查询参数中的访问令牌。

### 5.1.1. 授权请求头字段

当使用 HTTP/1.1 [RFC7235] 定义的 Authorization 请求头字段发送访问令牌时，客户端使用 Bearer 方案来传输访问令牌。

例如：

```
GET /resource HTTP/1.1
Host: server.example.com
Authorization: Bearer mF_9.B5f-4.1JqM
```

此方案的 Authorization 头字段语法遵循 [RFC2617] 第 2 节中定义的 Basic 的用法。请注意，与 Basic 一样，它不符合 [RFC2617] 第 1.2 节定义的通用语法，但与 HTTP 1.1 认证框架 [RFC7235] 兼容，尽管它没有遵循其中的首选做法以反映现有部署。Bearer 凭证的语法如下：

```
token68    = 1*( ALPHA / DIGIT /
                   "-" / "." / "_" / "~" / "+" / "/" ) *"="
credentials = "bearer" 1*SP token68
```

客户端应使用带有 Bearer HTTP 认证方案的 Authorization 请求头字段发出带有持有者令牌的认证请求。资源服务器必须支持此方法。

如 [RFC9110] 第 11.1 节所述，字符串 bearer 不区分大小写。这意味着以下所有都是有效的 Authorization 头用法：

* `Authorization: Bearer mF_9.B5f-4.1JqM`

* `Authorization: bearer mF_9.B5f-4.1JqM`

* `Authorization: BEARER mF_9.B5f-4.1JqM`

* `Authorization: bEaReR mF_9.B5f-4.1JqM`

### 5.1.2. 表单编码内容参数

当在 HTTP 请求内容中发送访问令牌时，客户端使用 access_token 参数将访问令牌添加到请求内容中。客户端不得使用此方法，除非满足以下所有条件：

* HTTP 请求包含设置为 application/x-www-form-urlencoded 的 Content-Type 头字段。

* 内容遵循 URL Living Standard [WHATWG.URL] 定义的 application/x-www-form-urlencoded 内容类型的编码要求。

* HTTP 请求内容是单部分的。

* 请求中要编码的内容必须完全由 ASCII [USASCII] 字符组成。

* HTTP 请求方法是内容有定义语义的方法之一。特别是，这意味着不得使用 GET 方法。

内容可以包括其他特定于请求的参数，在这种情况下，access_token 参数必须使用 & 字符（ASCII 代码 38）与特定于请求的参数正确分隔。

例如，客户端使用传输层安全发出以下 HTTP 请求：

```
POST /resource HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded

access_token=mF_9.B5f-4.1JqM
```

除非在参与的客户端无法访问 Authorization 请求头字段的应用程序上下文中，否则不应使用 application/x-www-form-urlencoded 方法。资源服务器可以支持此方法。

## 5.2. 访问令牌验证

在收到访问令牌后，资源服务器必须检查访问令牌尚未过期、有权访问请求的资源、具有适当的作用域，以及满足资源服务器访问受保护资源的其他策略要求。

访问令牌通常分为两类：引用令牌或自编码令牌。引用令牌可以通过查询授权服务器或在令牌数据库中查找来验证，而自编码令牌包含加密和/或签名的字符串形式的授权信息，资源服务器可以提取。

查询授权服务器检查访问令牌有效性的标准化方法在令牌 Introspection [RFC7662] 中定义。

在令牌字符串中编码信息的标准化方法在 JWT Profile for Access Tokens [RFC9068] 中定义。

有关创建和验证访问令牌的其他注意事项，请参见第 7.1 节。

## 5.3. 错误响应

如果资源访问请求失败，资源服务器应告知客户端错误。错误响应的详细信息由特定令牌类型决定，如第 5.3.2 节中描述的持有者令牌。

### 5.3.1. WWW-Authenticate 响应头字段

如果受保护资源请求不包含认证凭证或不包含允许访问受保护资源的访问令牌，资源服务器必须包含 HTTP WWW-Authenticate 响应头字段；在其他情况下也可以包含它。WWW-Authenticate 头字段使用 HTTP/1.1 [RFC7235] 定义的框架。

此令牌类型的所有挑战必须使用 auth-scheme 值 Bearer。此方案后面必须跟随一个或多个 auth-param 值。本规范为此次令牌类型使用或定义的 auth-param 属性如下。其他 auth-param 属性也可以使用。

**"realm"**：可以包含 realm 属性，以 [RFC7235] 中描述的方式指示保护范围。realm 属性不得出现多次。

**"scope"**：scope 属性在第 1.4.1 节中定义。scope 属性是一个空格分隔的区分大小写的作用域值列表，指示访问令牌访问请求资源所需的作用域。作用域值是实现定义的；没有集中注册表；允许的值由授权服务器定义。作用域值的顺序不重要。在某些情况下，作用域值将用于请求具有足够访问作用域的新访问令牌以使用受保护资源。scope 属性的使用是可选的。scope 属性不得出现多次。scope 值用于编程目的，不面向最终用户显示。

两个示例 scope 值如下；这些分别取自 OpenID Connect [OpenID.Messages] 和开放认证技术委员会（OATC）在线多媒体授权协议 [OMAP] OAuth 2.0 用例：

```
scope="openid profile email"
scope="urn:example:channel=HBO&urn:example:rating=G,PG-13"
```

**"error"**：如果受保护资源请求包含访问令牌但认证失败，资源服务器应包含 error 属性，向客户端提供拒绝访问请求的原因。参数值在第 5.3.2 节中描述。

**"error_description"**：资源服务器可以包含 error_description 属性，为开发者提供人类可读的解释，不面向最终用户显示。

**"error_uri"**：资源服务器可以包含带有绝对 URI 的 error_uri 属性，标识解释错误的人类可读网页。

error、error_description 和 error_uri 属性不得出现多次。

scope 属性（见附录 A.4）的值不得包含用于表示作用域值的 %x21 / %x23-5B / %x5D-7E 集合之外的字符，以及作用域值之间分隔符的 %x20。error 和 error_description 属性（见附录 A.7 和附录 A.8）的值不得包含 %x20-21 / %x23-5B / %x5D-7E 集合之外的字符。error_uri 属性（见附录 A.9）的值必须符合 URI-reference 语法，因此不得包含 %x21 / %x23-5B / %x5D-7E 集合之外的字符。

### 5.3.2. 错误代码

当请求失败时，资源服务器使用适当的 HTTP 状态码（通常为 400、401、403 或 405）进行响应，并在响应中包含以下错误代码之一：

**"invalid_request"**：请求缺少必需的参数、包含不支持的参数或参数值、重复相同的参数、使用多种方法包含访问令牌，或格式不正确。资源服务器应使用 HTTP 400（Bad Request）状态码进行响应。

**"invalid_token"**：提供的访问令牌已过期、撤销、格式错误或因其他原因无效。资源服务器应使用 HTTP 401（Unauthorized）状态码进行响应。客户端可以请求新的访问令牌并重试受保护资源请求。

**"insufficient_scope"**：请求需要比授予客户端的作用域（由访问令牌表示）更高的特权（作用域）。资源服务器应使用 HTTP 403（Forbidden）状态码进行响应，并可以包含 scope 属性以及访问受保护资源所需的作用域。

扩展可以定义额外的错误代码或指定返回上述错误代码的其他情况。

如果请求缺少任何认证信息（例如，客户端不知道需要进行认证或尝试使用不支持的认证方法），资源服务器不应包含错误代码或其他错误信息。

例如：

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example"
```

以及响应使用过期访问令牌的受保护资源请求：

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example",
                  error="invalid_token",
                  error_description="The access token expired"
```
