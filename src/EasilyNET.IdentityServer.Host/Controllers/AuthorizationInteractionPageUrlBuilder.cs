using EasilyNET.IdentityServer.Abstractions.Extensions;
using Microsoft.AspNetCore.Http;

namespace EasilyNET.IdentityServer.Host.Controllers;

internal static class AuthorizationInteractionPageUrlBuilder
{
    public static string BuildEntryUrl(HttpRequest request, IdentityServerOptions options, string requestId)
    {
        var entryPath = NormalizeAbsolutePath(options.InteractionPageEntryPath, "/connect/authorize/interaction/page");
        return BuildAbsoluteUrl(request, $"{entryPath.TrimEnd('/')}/{Uri.EscapeDataString(requestId)}");
    }

    public static string BuildUiUrl(HttpRequest request, IdentityServerOptions options, string requestId)
    {
        var configuredPath = string.IsNullOrWhiteSpace(options.InteractionPagePath) ? "/authorize/interaction" : options.InteractionPagePath.Trim();
        if (Uri.TryCreate(configuredPath, UriKind.Absolute, out var absoluteUri))
        {
            return AppendRequestId(absoluteUri.ToString(), requestId);
        }

        var absolutePath = NormalizeAbsolutePath(configuredPath, "/authorize/interaction");
        return AppendRequestId(BuildAbsoluteUrl(request, absolutePath), requestId);
    }

    private static string AppendRequestId(string baseUrl, string requestId)
    {
        var separator = baseUrl.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        return $"{baseUrl}{separator}requestId={Uri.EscapeDataString(requestId)}";
    }

    private static string BuildAbsoluteUrl(HttpRequest request, string path)
    {
        var baseUri = $"{request.Scheme}://{request.Host.Value}";
        return $"{baseUri}{path}";
    }

    private static string NormalizeAbsolutePath(string? configuredPath, string fallback)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return fallback;
        }

        return configuredPath.StartsWith('/', StringComparison.Ordinal) ? configuredPath : $"/{configuredPath}";
    }
}