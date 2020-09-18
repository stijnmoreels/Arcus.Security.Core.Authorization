

// ReSharper disable once CheckNamespace
namespace System.Security.Authorization
{
    /// <summary>
    /// Exception thrown when the authorization of a system fails.
    /// </summary>
    [Serializable]
    public class AuthorizationException : SystemException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizationException"/> class.
        /// </summary>
        public AuthorizationException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizationException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the exception.</param>
        public AuthorizationException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizationException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public AuthorizationException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
