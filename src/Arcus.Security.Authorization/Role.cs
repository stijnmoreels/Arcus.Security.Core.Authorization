using System;

namespace Arcus.Security.Authorization
{
    /// <summary>
    /// Describes a role within the application.
    /// </summary>
    [Flags]
    public enum Role
    {
        /// <summary>
        /// Specifies that the consumer should only read resources.
        /// </summary>
        Reader = 1,

        /// <summary>
        /// Specifies that the consumer should be able to read and write resources.
        /// </summary>
        Writer = 3,

        /// <summary>
        /// Specifies that the consumer should be able to do all the available functionality.
        /// </summary>
        Admin = 7
    }
}