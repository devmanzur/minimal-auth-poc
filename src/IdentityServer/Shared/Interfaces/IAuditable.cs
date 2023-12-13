namespace IdentityServer.Shared.Interfaces;

public interface IAuditable
{
    public  Guid Version { get; set; }
    public DateTime? CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
}