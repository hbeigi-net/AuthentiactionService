namespace Application.Core;

public class JwtSettings
{
    public required string SecretKey { get; set; }
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public int AccessTokenExpirationMinutes { get; set; }
    public int RefreshTokenExpirationDays { get; set; }
    public required string RefreshTokenSecretKey {get;set;}
    public int RefreshTokenSecretKeyExpirationMinutes {get;set;}
}

