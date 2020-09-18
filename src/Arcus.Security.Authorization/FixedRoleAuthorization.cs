using System;
using System.Threading.Tasks;
using GuardNet;

namespace Arcus.Security.Authorization
{
    /// <summary>
    /// Represents an <see cref="IRoleAuthorization"/> implementation that determines whether a given <see cref="Role"/> is considered authorized or not.
    /// </summary>
    public class FixedRoleAuthorization : IRoleAuthorization
    {
        private readonly Role _currentRole;

        /// <summary>
        /// Initializes a new instance of the <see cref="FixedRoleAuthorization"/> class.
        /// </summary>
        /// <param name="currentRole">The role that is considered authorized in this context.</param>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="currentRole"/> is outside the bounds of the enumeration.</exception>
        public FixedRoleAuthorization(Role currentRole)
        {
            Guard.For<ArgumentOutOfRangeException>(() => !Enum.IsDefined(typeof(Role), currentRole), "Requires the authorized role to be inside the bounds of the enumeration");
            _currentRole = currentRole;
        }

        /// <summary>
        /// Gets the <see cref="IRoleAuthorization"/> implementation that considers consumers within the <see cref="Role.Reader"/> role authorized.
        /// </summary>
        public static IRoleAuthorization Reader { get; } = new FixedRoleAuthorization(Role.Reader);

        /// <summary>
        /// Gets the <see cref="IRoleAuthorization"/> implementation that considers consumers within the <see cref="Role.Writer"/> role authorized.
        /// </summary>
        public static IRoleAuthorization Writer { get; } = new FixedRoleAuthorization(Role.Writer);

        /// <summary>
        /// Gets the <see cref="IRoleAuthorization"/> implementation that considers consumers within the <see cref="Role.Admin"/> role authorized.
        /// </summary>
        public static IRoleAuthorization Admin { get; } = new FixedRoleAuthorization(Role.Admin);

        /// <summary>
        /// Determines if the given <paramref name="permittedRole"/> is considered authorized in this context.
        /// </summary>
        /// <param name="permittedRole">The permitted role in this context.</param>
        /// <returns>
        ///     [true] if the given <paramref name="permittedRole"/> is considered authorized in this context; [false] otherwise.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="permittedRole"/> is outside the bounds of the enumeration.</exception>
        public Task<bool> IsAuthorizedAsync(Role permittedRole)
        {
            Guard.For<ArgumentOutOfRangeException>(() => !Enum.IsDefined(typeof(Role), permittedRole), "Requires the current authorized role to be inside the bounds of the enumeration");
            return Task.FromResult((_currentRole & permittedRole) == permittedRole);
        }
    }
}