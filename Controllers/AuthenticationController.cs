using System.Collections.Immutable;
using System.Security.Claims;
using authServer.Entities;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace authServer.Controllers;
[ApiExplorerSettings(IgnoreApi = true)]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IOpenIddictApplicationManager _appManager;
    private readonly IOpenIddictScopeManager _scopeManager;

    public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, SignInManager<ApplicationUser> signInManager, IOpenIddictApplicationManager appManager, IOpenIddictScopeManager scopeManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _appManager = appManager;
        _scopeManager = scopeManager;
    }

    [HttpPost("~/connect/token")]
    [Consumes("application/x-www-form-urlencoded")]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var oidcRequest = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        if (oidcRequest.IsPasswordGrantType())
        {
            return await TokensForPasswordGrantType(oidcRequest);
        }
        if (oidcRequest.IsRefreshTokenGrantType())
        {
            return await TokensForRefreshTokenGrantType();
        }

        return BadRequest(new OpenIddictResponse
        {
            Error = OpenIddictConstants.Errors.UnsupportedGrantType
        });
    }

    private async Task<IActionResult> TokensForPasswordGrantType(OpenIddictRequest request)
    {
        var tmp = _userManager.Users.Include(u => u.UserRoles).ThenInclude(u => u.Role);
        var user = await tmp.FirstOrDefaultAsync(x => x.UserName == request.Username);
        if (user == null) return Unauthorized();

        var signInResult = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
        if (signInResult.Succeeded)
        {
            var identity = new ClaimsIdentity(
                TokenValidationParameters.DefaultAuthenticationType,
                OpenIddictConstants.Claims.Name,
                OpenIddictConstants.Claims.Role);

            identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id.ToString(), OpenIddictConstants.Destinations.AccessToken);
            identity.AddClaim(OpenIddictConstants.Claims.Username, user.UserName, OpenIddictConstants.Destinations.AccessToken);
            // Add more claims if necessary

            foreach (var userRole in user.UserRoles)
            {
                identity.AddClaim(OpenIddictConstants.Claims.Role, userRole.Role.NormalizedName, OpenIddictConstants.Destinations.AccessToken);
            }

            var claimsPrincipal = new ClaimsPrincipal(identity);
            var scopes = request.GetScopes();
            claimsPrincipal.SetScopes(new string[]{
                    OpenIddictConstants.Scopes.Roles,
                    OpenIddictConstants.Scopes.OfflineAccess,
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Profile,
            }.Union(scopes));

            var resources = await _scopeManager.ListResourcesAsync(scopes).ToListAsync();
            claimsPrincipal.SetResources(resources);

            foreach (var claim in claimsPrincipal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim));
            }

            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        else
        {
            return Unauthorized();
        }
    }

    private async Task<IActionResult> TokensForRefreshTokenGrantType()
    {
        var tmp = _userManager.Users.Include(u => u.UserRoles).ThenInclude(u => u.Role);
        var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        return claim.Type switch
        {
            OpenIddictConstants.Claims.Name or
            OpenIddictConstants.Claims.Subject or
            OpenIddictConstants.Claims.Role or
            OpenIddictConstants.Claims.Username or
            OpenIddictConstants.Claims.Email or
            OpenIddictConstants.Claims.Audience or
            OpenIddictConstants.Claims.TokenUsage or
            OpenIddictConstants.Claims.Nonce or
            OpenIddictConstants.Claims.AccessTokenHash
                => ImmutableArray.Create(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken),
            _ => ImmutableArray.Create(OpenIddictConstants.Destinations.AccessToken),
        };
    }
}