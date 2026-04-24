# 附录 A. 增强巴科斯-诺尔形式（ABNF）语法

本节使用 [RFC5234] 的表示法提供本规范中定义元素的增强巴科斯-诺尔形式（ABNF）语法描述。下面的 ABNF 根据 Unicode 代码点 [W3C.REC-xml-20081126] 定义；这些字符通常以 UTF-8 编码。元素按首次定义的顺序呈现。

以下某些定义使用 [RFC3986] 中的"URI-reference"定义。

以下某些定义使用这些常用定义：

```
VSCHAR     = %x20-7E
NQCHAR     = %x21 / %x23-5B / %x5D-7E
NQSCHAR    = %x20-21 / %x23-5B / %x5D-7E
```

## A.1. "client_id" 语法

client_id 元素在第 2.4.1 节中定义：

```
client-id     = *VSCHAR
```

## A.2. "client_secret" 语法

client_secret 元素在第 2.4.1 节中定义：

```
client-secret = *VSCHAR
```

## A.3. "response_type" 语法

response_type 元素在第 4.1.1 节和第 6.4 节中定义：

```
response-type = response-name *( SP response-name )
response-name = 1*response-char
response-char = "_" / DIGIT / ALPHA
```

## A.4. "scope" 语法

scope 元素在第 1.4.1 节中定义：

```
scope       = scope-token *( SP scope-token )
scope-token = 1*NQCHAR
```

## A.5. "state" 语法

state 元素在第 4.1.1 节、第 4.1.2 节和第 4.1.2.1 节中定义：

```
state      = 1*VSCHAR
```

## A.6. "redirect_uri" 语法

redirect_uri 元素在第 4.1.1 节和第 4.1.3 节中定义：

```
redirect-uri      = URI-reference
```

## A.7. "error" 语法

error 元素在第 4.1.2.1 节、第 3.2.4 节和第 5.3 节中定义：

```
error             = 1*NQSCHAR
```

## A.8. "error_description" 语法

error_description 元素在第 4.1.2.1 节、第 3.2.4 节和第 5.3 节中定义：

```
error-description = 1*NQSCHAR
```

## A.9. "error_uri" 语法

error_uri 元素在第 4.1.2.1 节、第 3.2.4 节和第 5.3 节中定义：

```
error-uri         = URI-reference
```

## A.10. "grant_type" 语法

grant_type 元素在第 3.2.2 节中定义：

```
grant-type = grant-name / URI-reference
grant-name = 1*name-char
name-char  = "-" / "." / "_" / DIGIT / ALPHA
```

## A.11. "code" 语法

code 元素在第 4.1.3 节中定义：

```
code       = 1*VSCHAR
```

## A.12. "access_token" 语法

access_token 元素在第 3.2.3 节中定义：

```
access-token = 1*VSCHAR
```

## A.13. "token_type" 语法

token_type 元素在第 3.2.3 节和第 6.1 节中定义：

```
token-type = type-name / URI-reference
type-name  = 1*name-char
name-char  = "-" / "." / "_" / DIGIT / ALPHA
```

## A.14. "expires_in" 语法

expires_in 元素在第 3.2.3 节中定义：

```
expires-in = 1*DIGIT
```

## A.15. "refresh_token" 语法

refresh_token 元素在第 3.2.3 节和第 4.3 节中定义：

```
refresh-token = 1*VSCHAR
```

## A.16. 端点参数语法

新端点参数的语法在第 6.2 节中定义：

```
param-name = 1*name-char
name-char  = "-" / "." / "_" / DIGIT / ALPHA
```

## A.17. "code_verifier" 语法

code_verifier 的 ABNF 如下：

```
code-verifier = 43*128unreserved
unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
ALPHA = %x41-5A / %x61-7A
DIGIT = %x30-39
```

## A.18. "code_challenge" 语法

code_challenge 的 ABNF 如下：

```
code-challenge = 43*128unreserved
unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
ALPHA = %x41-5A / %x61-7A
DIGIT = %x30-39
```

# 附录 B. application/x-www-form-urlencoded 媒体类型的使用

在 [RFC6749] 发布时，application/x-www-form-urlencoded 媒体类型在 [W3C.REC-html401-19991224] 的第 17.13.4 节中定义，但未在 IANA MIME 媒体类型注册表中注册（http://www.iana.org/assignments/media-types (http://www.iana.org/assignments/media-types/)）。此外，该定义不完整，因为它没有考虑非 US-ASCII 字符。

为了在使用此媒体类型生成内容时解决此缺陷，名称和值必须首先使用 UTF-8 字符编码方案 [RFC3629] 进行编码；然后需要使用 [W3C.REC-html401-19991224] 中定义的转义规则进一步编码结果字节序列。

从使用此媒体类型的内容解析数据时，由此产生的名称/值编码的结果需要被视为字节序列，使用 UTF-8 字符编码方案进行解码。

例如，由六个 Unicode 代码点组成 的值：（1）U+0020（空格），（2）U+0025（百分号），（3）U+0026（和号），（4）U+002B（加号），（5）U+00A3（英镑符号）和（6）U+20AC（欧元符号）将编码为以下字节序列（使用十六进制表示法）：

```
20 25 26 2B C2 A3 E2 82 AC
```

然后在内容中表示为：

```
+%25%26%2B%C2%A3%E2%82%AC
```

# 附录 C. 序列化

本规范中的各种消息使用以下描述的方法之一进行序列化。本节描述这些序列化方法的语法；其他节描述何时可以使用和必须使用它们。请注意，并非所有方法都可用于所有消息。

## C.1. 查询字符串序列化

为了使用查询字符串序列化对参数进行序列化，客户端通过使用 [WHATWG.URL] 定义的 application/x-www-form-urlencoded 格式将参数和值添加到 URL 的查询组件来构建字符串。查询字符串序列化通常用于 HTTP GET 请求。

## C.2. 表单编码序列化

参数及其值通过使用附录 B 中定义的 application/x-www-form-urlencoded 格式将参数名称和值添加到 HTTP 请求的实体正文来进行表单序列化。表单序列化通常用于 HTTP POST 请求。

## C.3. JSON 序列化

参数通过在最高结构级别添加每个参数来序列化为 JSON [RFC8259] 对象结构。参数名称和字符串值表示为 JSON 字符串。数值表示为 JSON 数字。布尔值表示为 JSON 布尔值。除非另有指定，否则应省略省略的参数和没有值的参数，而不是用 JSON null 值表示。参数可以具有 JSON 对象或其值作为 JSON 数组。参数的顺序不重要，可能会有所不同。

# 附录 D. 扩展

以下是发布时的成熟扩展列表：

**[RFC7009]：令牌撤销**

* 令牌撤销扩展定义了一种机制，客户端可据此向授权服务器指示访问令牌不再需要。

**[RFC7591]：动态客户端注册**

* 动态客户端注册提供了一种向授权服务器以编程方式注册客户端的机制。

**[RFC7662]：令牌 Introspection**

* 令牌 Introspection 扩展定义了资源服务器获取访问令牌信息的一种机制。

**[RFC8414]：授权服务器元数据**

* 授权服务器元数据（也称为 OAuth Discovery）定义了一个端点，客户端可使用它来查找与特定 OAuth 服务器交互所需的信息，例如授权和令牌端点的位置以及支持的授权类型。

**[RFC8628]：OAuth 2.0 设备授权许可**

* 设备授权许可（以前称为设备流）是一种扩展，使没有浏览器或有限输入能力的设备能够获取访问令牌。这通常被智能电视应用程序或可以向流媒体视频服务流式传输视频的硬件视频编码器等设备使用。

**[RFC8705]：Mutual TLS**

* Mutual TLS 描述了一种通过 TLS 证书认证将令牌绑定到颁发给的客户端以及客户端认证机制的机制。

**[RFC8707]：资源指示器**

* 为客户端提供了一种明确地向授权服务器发出信号表明其打算使用正在请求的访问令牌的位置的方式。

**[RFC9068]：OAuth 2.0 访问令牌的 JSON Web Token (JWT) 配置文件**

* 此规范定义了一种以 JSON Web Token (JWT) 格式颁发 OAuth 访问令牌的配置文件。

**[RFC9126]：推送授权请求**

* 推送授权请求扩展描述了一种从后通道启动 OAuth 流程的技术，为构建复杂授权请求提供了更好的安全性和更多灵活性。

**[RFC9207]：授权服务器颁发者标识**

* 授权响应中的 iss 参数指示授权服务器的身份，以防止客户端中的混消攻击。

**[RFC9396]：丰富授权请求**

* 丰富授权请求指定了一个新参数 authorization_details，用于在 OAuth 授权请求中携带细粒度授权数据。

**[RFC9449]：占有证明 (DPoP)**

* DPoP 描述了一种通过应用级别的占有证明机制来发送者约束 OAuth 2.0 令牌的机制。

**[RFC9470]：步进认证挑战协议**

* 步进认证描述了一种资源服务器可用于向客户端发信号表明与当前请求访问令牌关联的认证事件不满足其认证要求的机制。
