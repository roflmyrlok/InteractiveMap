using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace ReviewService.API.Services;

public static class JwtHelper
{
	public static Guid GetUserIdFromToken(ClaimsPrincipal user)
	{
		var userIdClaim = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        
		if (string.IsNullOrEmpty(userIdClaim))
		{
			// Fallback 1
			userIdClaim = user.FindFirst(JwtRegisteredClaimNames.NameId)?.Value;
		}
        
		if (string.IsNullOrEmpty(userIdClaim))
		{
			// Fallback 2
			userIdClaim = user.Claims.FirstOrDefault(c => 
				c.Type.Contains("userid", StringComparison.OrdinalIgnoreCase))?.Value;
		}
        
		if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
		{
			//idk go get new token
			throw new UnauthorizedAccessException("Invalid or missing user identifier in the token");
		}
        
		return userId;
	}
    
	public static string GetUserRoleFromToken(ClaimsPrincipal user)
	{
		var roleClaim = user.FindFirst(ClaimTypes.Role)?.Value;
		if (string.IsNullOrEmpty(roleClaim))
		{
			roleClaim = user.Claims.FirstOrDefault(c => 
				c.Type.Contains("role", StringComparison.OrdinalIgnoreCase))?.Value;
		}
        
		return roleClaim ?? "Regular";
	}
}