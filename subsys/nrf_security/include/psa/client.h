/*
 * Copyright (c) 2018-2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __PSA_CLIENT_H__
#define __PSA_CLIENT_H__

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IOVEC_LEN
#define IOVEC_LEN(arr) ((uint32_t)(sizeof(arr)/sizeof(arr[0])))
#endif

/*********************** PSA Client Macros and Types *************************/

/**
 * The version of the PSA Framework API that is being used to build the calling
 * firmware. Only part of features of FF-M v1.1 have been implemented. FF-M v1.1
 * is compatible with v1.0.
 */
#define PSA_FRAMEWORK_VERSION       (0x0101u)

/**
 * Return value from psa_version() if the requested RoT Service is not present
 * in the system.
 */
#define PSA_VERSION_NONE            (0u)

/**
 * The zero-value null handle can be assigned to variables used in clients and
 * RoT Services, indicating that there is no current connection or message.
 */
#define PSA_NULL_HANDLE             ((psa_handle_t)0)

/**
 * Tests whether a handle value returned by psa_connect() is valid.
 */
#define PSA_HANDLE_IS_VALID(handle) ((psa_handle_t)(handle) > 0)

/**
 * Converts the handle value returned from a failed call psa_connect() into
 * an error code.
 */
#define PSA_HANDLE_TO_ERROR(handle) ((psa_status_t)(handle))

/**
 * Maximum number of input and output vectors for a request to psa_call().
 */
#define PSA_MAX_IOVEC               (4u)


/**
 * The minimum and maximum value in THIS implementation that can be passed
 * as the type parameter in a call to psa_call().
 */

#define PSA_CALL_TYPE_MIN           (0)
#define PSA_CALL_TYPE_MAX           (INT16_MAX)

/**
 * An IPC message type that indicates a generic client request.
 */
#define PSA_IPC_CALL                (0)

typedef int32_t psa_handle_t;

/**
 * A read-only input memory region provided to an RoT Service.
 */
typedef struct psa_invec {
    const void *base;           /*!< the start address of the memory buffer */
    size_t len;                 /*!< the size in bytes                      */
} psa_invec;

/**
 * A writable output memory region provided to an RoT Service.
 */
typedef struct psa_outvec {
    void *base;                 /*!< the start address of the memory buffer */
    size_t len;                 /*!< the size in bytes                      */
} psa_outvec;

/*************************** PSA Client API **********************************/

/**
 * \brief Retrieve the version of the PSA Framework API that is implemented.
 *
 * \return version              The version of the PSA Framework implementation
 *                              that is providing the runtime services to the
 *                              caller. The major and minor version are encoded
 *                              as follows:
 * \arg                           version[15:8] -- major version number.
 * \arg                           version[7:0]  -- minor version number.
 */
uint32_t psa_framework_version(void);

/**
 * \brief Retrieve the version of an RoT Service or indicate that it is not
 *        present on this system.
 *
 * \param[in] sid               ID of the RoT Service to query.
 *
 * \retval PSA_VERSION_NONE     The RoT Service is not implemented, or the
 *                              caller is not permitted to access the service.
 * \retval > 0                  The version of the implemented RoT Service.
 */
uint32_t psa_version(uint32_t sid);

/**
 * \brief Connect to an RoT Service by its SID.
 *
 * The call is invalid if one or more of the following are true:
 * - The RoT Service ID is not present.
 * - The RoT Service version is not supported.
 * - The caller is not allowed to access the RoT service.
 * \param[in] sid               ID of the RoT Service to connect to.
 * \param[in] version           Requested version of the RoT Service.
 *
 * \retval > 0                  A handle for the connection.
 * \retval PSA_ERROR_CONNECTION_REFUSED The SPM or RoT Service has refused the
 *                              connection.
 * \retval PSA_ERROR_CONNECTION_BUSY The SPM or RoT Service cannot make the
 *                              connection at the moment.
 */
psa_handle_t psa_connect(uint32_t sid, uint32_t version);

/**
 * \brief Call an RoT Service on an established connection.
 *
 * \note  FF-M 1.0 proposes 6 parameters for psa_call but the secure gateway ABI
 *        support at most 4 parameters. TF-M chooses to encode 'in_len',
 *        'out_len', and 'type' into a 32-bit integer to improve efficiency.
 *        Compared with struct-based encoding, this method saves extra memory
 *        check and memory copy operation. The disadvantage is that the 'type'
 *        range has to be reduced into a 16-bit integer. So with this encoding,
 *        the valid range for 'type' is 0-32767.
 *
 * The call is invalid if one or more of the following are true:
 * - An invalid handle was passed.
 * - The connection is already handling a request.
 * - type < 0.
 * - An invalid memory reference was provided.
 * - in_len + out_len > PSA_MAX_IOVEC.
 * - The message is unrecognized by the RoT Service or incorrectly formatted.
 *
 * \param[in] handle            A handle to an established connection.
 * \param[in] type              The request type.
 *                              Must be zero( \ref PSA_IPC_CALL) or positive.
 * \param[in] in_vec            Array of input \ref psa_invec structures.
 * \param[in] in_len            Number of input \ref psa_invec structures.
 * \param[in,out] out_vec       Array of output \ref psa_outvec structures.
 * \param[in] out_len           Number of output \ref psa_outvec structures.
 *
 * \retval >=0                  RoT Service-specific status value.
 * \retval <0                   RoT Service-specific error code.
 */
psa_status_t psa_call(psa_handle_t handle, int32_t type,
                      const psa_invec *in_vec,
                      size_t in_len,
                      psa_outvec *out_vec,
                      size_t out_len);

/**
 * \brief Close a connection to an RoT Service.
 *
 * The call is invalid if one or more of the following are true:
 * - An invalid handle was provided that is not the null handle.
 * - The connection is currently handling a request.
 *
 * \param[in] handle            A handle to an established connection, or the
 *                              null handle.
 */
void psa_close(psa_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* __PSA_CLIENT_H__ */
