

using System.ComponentModel;

namespace SingPassAuthentication
{
    /// <summary>
    /// SingPass only support ES256, ES384, ES512 signing algorithm.
    /// </summary>
    public enum SigningAlgorithm
    {
        [Description("ES256")]
        ES256 = 1,
        [Description("ES384")]
        ES384 = 2,
        [Description("ES512")]
        ES512 = 3
    }
}
