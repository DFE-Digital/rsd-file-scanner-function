using GovUK.Dfe.CoreLibs.Messaging.Contracts.Messages.Events;
using System.Text.Json.Serialization;

namespace GovUK.Dfe.FileScanner.Models;

/// <summary>
/// Helper class to deserialize the Service Bus message wrapper.
/// </summary>
public sealed class MessageWrapper
{
    [JsonPropertyName("message")]
    public ScanRequestedEvent? Message { get; init; }
}

