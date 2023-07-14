using System.Security.Claims;
using ApiKeyGenerator.Interfaces;

namespace ApiKeyGenerator.Benchmarks;

public class PersistedKey : IPersistedApiKey
{
    public Guid ApiKeyId { get; set; }
    public string Salt { get; set; } = string.Empty;
    public string Hash { get; set; } = string.Empty;
    public string KeyName { get; set; } = string.Empty;
    public bool? IsRevoked { get; set; }
    public DateTime? ExpirationDate { get; set; }
    public List<Claim> Claims { get; set; } = new();
}