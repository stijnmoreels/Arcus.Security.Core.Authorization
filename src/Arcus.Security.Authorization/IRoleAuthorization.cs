using System;
using System.Threading.Tasks;

namespace Arcus.Security.Authorization
{
    /// <summary>
    /// Represents a contract to determine whether a given <see cref="Role"/> is considered authorized in this part of the application.
    /// </summary>
    public interface IRoleAuthorization
    {
        /// <summary>
        /// Determines if the given <paramref name="permittedRole"/> is considered authorized in this context.
        /// </summary>
        /// <param name="permittedRole">The current role in this context.</param>
        /// <returns>
        ///     [true] if the given <paramref name="permittedRole"/> is considered authorized in this context; [false] otherwise.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="permittedRole"/> is outside the bounds of the enumeration.</exception>
        Task<bool> IsAuthorizedAsync(Role permittedRole);
    }
}