// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.
namespace Microsoft.Azure.Management.RecoveryServices.Backup
{
    using Microsoft.Rest.Azure;
    using Models;

    /// <summary>
    /// Extension methods for ResourceGuardProxiesOperations
    /// </summary>
    public static partial class ResourceGuardProxiesOperationsExtensions
    {
        /// <summary>
        /// List the ResourceGuardProxies under vault
        /// </summary>
        /// <param name='operations'>
        /// The operations group for this extension method.
        /// </param>
        /// <param name='vaultName'>
        /// The name of the recovery services vault.
        /// </param>
        /// <param name='resourceGroupName'>
        /// The name of the resource group where the recovery services vault is present.
        /// </param>
        public static Microsoft.Rest.Azure.IPage<ResourceGuardProxyBaseResource> Get(this IResourceGuardProxiesOperations operations, string vaultName, string resourceGroupName)
        {
                return ((IResourceGuardProxiesOperations)operations).GetAsync(vaultName, resourceGroupName).GetAwaiter().GetResult();
        }

        /// <summary>
        /// List the ResourceGuardProxies under vault
        /// </summary>
        /// <param name='operations'>
        /// The operations group for this extension method.
        /// </param>
        /// <param name='vaultName'>
        /// The name of the recovery services vault.
        /// </param>
        /// <param name='resourceGroupName'>
        /// The name of the resource group where the recovery services vault is present.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        public static async System.Threading.Tasks.Task<Microsoft.Rest.Azure.IPage<ResourceGuardProxyBaseResource>> GetAsync(this IResourceGuardProxiesOperations operations, string vaultName, string resourceGroupName, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            using (var _result = await operations.GetWithHttpMessagesAsync(vaultName, resourceGroupName, null, cancellationToken).ConfigureAwait(false))
            {
                return _result.Body;
            }
        }
        /// <summary>
        /// List the ResourceGuardProxies under vault
        /// </summary>
        /// <param name='operations'>
        /// The operations group for this extension method.
        /// </param>
        /// <param name='nextPageLink'>
        /// The NextLink from the previous successful call to List operation.
        /// </param>
        public static Microsoft.Rest.Azure.IPage<ResourceGuardProxyBaseResource> GetNext(this IResourceGuardProxiesOperations operations, string nextPageLink)
        {
                return ((IResourceGuardProxiesOperations)operations).GetNextAsync(nextPageLink).GetAwaiter().GetResult();
        }

        /// <summary>
        /// List the ResourceGuardProxies under vault
        /// </summary>
        /// <param name='operations'>
        /// The operations group for this extension method.
        /// </param>
        /// <param name='nextPageLink'>
        /// The NextLink from the previous successful call to List operation.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        public static async System.Threading.Tasks.Task<Microsoft.Rest.Azure.IPage<ResourceGuardProxyBaseResource>> GetNextAsync(this IResourceGuardProxiesOperations operations, string nextPageLink, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
        {
            using (var _result = await operations.GetNextWithHttpMessagesAsync(nextPageLink, null, cancellationToken).ConfigureAwait(false))
            {
                return _result.Body;
            }
        }
    }
}
