using System.Text.Json;
using Azure.Messaging.ServiceBus;
using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Events;
using GovUK.Dfe.CoreLibs.Messaging.MassTransit.Models;

namespace GovUK.Dfe.FileScanner;

/// <summary>
/// Copies tenant / template / user routing from the inbound scan request onto the result.
/// Isolation is applied in consumers (not Service Bus SQL filters) using these headers.
/// </summary>
internal static class ScanResultRouting
{
    public const string TenantIdHeader = "TenantId";
    public const string TenantNameHeader = "TenantName";
    public const string TemplateIdHeader = "TemplateId";
    public const string UserIdHeader = "UserId";
    public const string ServiceNameProperty = "serviceName";

    public const string TenantIdMetadata = "TenantId";
    public const string TenantNameMetadata = "TenantName";
    public const string TemplateIdMetadata = "templateId";
    public const string UserIdMetadata = "userId";

    public sealed record Values(
        string ServiceName,
        string? TenantId,
        string? TenantName,
        string? TemplateId,
        string? UserId);

    public static Values FromInbound(ServiceBusReceivedMessage message, ScanRequestedEvent request, string fallbackServiceName)
    {
        var serviceName = GetApplicationProperty(message, ServiceNameProperty)
            ?? request.ServiceName
            ?? fallbackServiceName;

        return new Values(
            ServiceName: string.IsNullOrWhiteSpace(serviceName) ? fallbackServiceName : serviceName,
            TenantId: GetApplicationProperty(message, TenantIdHeader)
                ?? GetMetadata(request.Metadata, TenantIdMetadata),
            TenantName: GetApplicationProperty(message, TenantNameHeader)
                ?? GetMetadata(request.Metadata, TenantNameMetadata),
            TemplateId: GetApplicationProperty(message, TemplateIdHeader)
                ?? GetMetadata(request.Metadata, TemplateIdMetadata),
            UserId: GetApplicationProperty(message, UserIdHeader)
                ?? GetMetadata(request.Metadata, UserIdMetadata));
    }

    public static AzureServiceBusMessageProperties ToMessageProperties(Values routing)
    {
        var builder = AzureServiceBusMessagePropertiesBuilder
            .Create()
            .AddCustomProperty(ServiceNameProperty, routing.ServiceName);

        AddIfPresent(builder, TenantIdHeader, routing.TenantId);
        AddIfPresent(builder, TenantNameHeader, routing.TenantName);
        AddIfPresent(builder, TemplateIdHeader, routing.TemplateId);
        AddIfPresent(builder, UserIdHeader, routing.UserId);

        return builder.Build();
    }

    /// <summary>
    /// Reuses the cached scan outcome but stamps the current requester's file identity and metadata.
    /// Prevents a hash cache hit from notifying or deleting for a different tenant/user.
    /// </summary>
    public static ScanResultEvent ForRequester(
        ScanResultEvent cachedOutcome,
        ScanRequestedEvent request,
        Values routing,
        string? correlationId) =>
        cachedOutcome with
        {
            FileId = request.FileId,
            FileName = request.FileName,
            Reference = request.Reference,
            Path = request.Path,
            IsAzureFileShare = request.IsAzureFileShare,
            FileUri = request.FileUri,
            ServiceName = routing.ServiceName,
            CorrelationId = correlationId,
            Metadata = request.Metadata
        };

    private static void AddIfPresent(AzureServiceBusMessagePropertiesBuilder builder, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            builder.AddCustomProperty(key, value);
    }

    private static string? GetApplicationProperty(ServiceBusReceivedMessage message, string key)
    {
        foreach (var property in message.ApplicationProperties)
        {
            if (string.Equals(property.Key, key, StringComparison.OrdinalIgnoreCase)
                && property.Value is not null)
            {
                var text = property.Value.ToString();
                if (!string.IsNullOrWhiteSpace(text))
                    return text;
            }
        }

        return null;
    }

    internal static string? GetMetadata(IDictionary<string, object>? metadata, string key)
    {
        if (metadata is null)
            return null;

        foreach (var pair in metadata)
        {
            if (!string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase))
                continue;

            var text = pair.Value switch
            {
                null => null,
                JsonElement element when element.ValueKind == JsonValueKind.String => element.GetString(),
                JsonElement element => element.ToString(),
                _ => pair.Value.ToString()
            };

            return string.IsNullOrWhiteSpace(text) ? null : text;
        }

        return null;
    }
}
