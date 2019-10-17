//
// Created by olve on 10/10/19.
//

#import "GCDWebServerTlsConnection.h"
#import "GCDWebServerPrivate.h"

static OSStatus SSLReadFunction(SSLConnectionRef connection, void *data, size_t *dataLength);
static OSStatus SSLWriteFunction(SSLConnectionRef connection, const void *data, size_t *dataLength);

@implementation GCDWebServerTlsConnection
{
    SSLContextRef _sslContext;
}

- (instancetype)initWithServer:(GCDWebServer *)server
                  localAddress:(NSData *)localAddress
                 remoteAddress:(NSData *)remoteAddress
                        socket:(CFSocketNativeHandle)socket
{
    _sslContext = SSLCreateContext(kCFAllocatorDefault, kSSLServerSide, kSSLStreamType);
    if (!_sslContext)
    {
        GWS_LOG_ERROR(@"%@: SSLContext failed to be created", self);
        return nil;
    }

    OSStatus status;

    status = SSLSetIOFuncs(_sslContext, &SSLReadFunction, &SSLWriteFunction);
    if (status != noErr)
    {
        GWS_LOG_ERROR(@"%@: SSLSetIOFuncs failed: %d", self, (int)status);
        return nil;
    }

    status = SSLSetConnection(_sslContext, (SSLConnectionRef) (intptr_t) socket);
    if (status != noErr)
    {
        GWS_LOG_ERROR(@"%@: SSLSetConnection failed: %d", self, (int)status);
        return nil;
    }

    status = SSLSetCertificate(_sslContext, (__bridge CFArrayRef) @[(__bridge id) server.tlsIdentity]);
    if (status != noErr)
    {
        GWS_LOG_ERROR(@"%@: SSLSetCertificate failed: %d", self, (int)status);
        return nil;
    }

    self = [super initWithServer:server
                    localAddress:localAddress
                   remoteAddress:remoteAddress
                          socket:socket];

    return self;
}

- (void)dealloc
{
    if (_sslContext) {
        SSLClose(_sslContext);
    }
}

- (BOOL)open
{
    if (![super open]) {
        return NO;
    }

    OSStatus status = SSLHandshake(self->_sslContext);
    if (status != noErr) {
        GWS_LOG_ERROR(@"%@: Handshake failed with status %d", self, (int)status);
    } else {
        GWS_LOG_INFO(@"%@: Handshake succeeded", self);
    }

    return status == noErr;
}

- (void)readData:(NSMutableData*)data withLength:(NSUInteger)length completionBlock:(ReadDataCompletionBlock)block
{
    size_t trimmedLength = MIN(2048, length);
    void *buffer = malloc(trimmedLength);

    size_t bytesRead = 0;
    OSStatus status = SSLRead(self->_sslContext, buffer, trimmedLength, &bytesRead);

    if (status != noErr || bytesRead == 0)
    {
        free(buffer);
        GWS_LOG_ERROR(@"%@: Failed to read data: %d", self.class, (int)status);
        block(NO);
        return;
    }

    NSUInteger originalLength = data.length;
    [data appendBytes:buffer
               length:bytesRead];
    free(buffer);

    [self didReadBytes:((char *) data.bytes + originalLength)
                length:(data.length - originalLength)];
    block(YES);
}

- (void)writeData:(NSData*)data withCompletionBlock:(WriteDataCompletionBlock)block
{
    size_t processed = 0;
    OSStatus status = SSLWrite(self->_sslContext, data.bytes, data.length, &processed);
    if (status != noErr) {
        GWS_LOG_ERROR(@"%@: Failed to write data securely %d", self.class, (int)status);
        block(NO);
        return;
    }

    [self didWriteBytes:data.bytes length:processed];
    block(YES);
}

@end


static OSStatus SSLReadFunction(SSLConnectionRef connection, void *data, size_t *dataLength) {

    size_t bytesRequested = *dataLength;
    ssize_t result = read((CFSocketNativeHandle) connection, data, bytesRequested);

    if (result >= 0) {
        size_t bytesRead = (size_t) result;

        *dataLength = bytesRead;
        return bytesRead == 0
            ? errSSLClosedGraceful
            : noErr;
    }

    int error = errno;
    GWS_LOG_ERROR(@"Read for TLS failed: %s", strerror(error));
    *dataLength = 0;

    switch (error)
    {
        case ENOENT:
            return errSSLClosedGraceful;
        case ECONNRESET:
            return errSSLClosedAbort;
        default:
            return errSecIO;
    }
}

static OSStatus SSLWriteFunction(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
    size_t bytesToWrite = *dataLength;
    ssize_t result = write((CFSocketNativeHandle) connection, data, bytesToWrite);

    if (result >= 0) {
        size_t bytesWritten = (size_t) result;

        *dataLength = bytesWritten;
        return bytesWritten == 0
            ? errSSLClosedGraceful
                : noErr;
    }

    int error = errno;
    GWS_LOG_ERROR(@"Write for TLS failed: %s", strerror(error));
    *dataLength = 0;

    return errSecIO;
}
