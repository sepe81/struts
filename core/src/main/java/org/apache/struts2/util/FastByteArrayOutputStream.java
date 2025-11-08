/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.struts2.util;

import jakarta.servlet.jsp.JspWriter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedList;
import java.util.UUID;

/**
 * A speedy implementation of ByteArrayOutputStream. It's not synchronized, and it
 * does not copy buffers when it's expanded. There's also no copying of the internal buffer
 * if it's contents is extracted with the writeTo(stream) method.
 *
 */
public class FastByteArrayOutputStream extends OutputStream {

    private static final Logger LOG = LogManager.getLogger(FastByteArrayOutputStream.class);

    private static final int DEFAULT_BLOCK_SIZE = 8192;

    /**
     * Application-specific temporary directory, initialized once when class is loaded.
     * This is used for secure temporary file creation with UUID-based naming.
     * May be null if directory creation fails during initialization.
     */
    private static final Path APP_TEMP_DIR = initializeAppTempDir();

    /**
     * Initializes the application temporary directory once when the class is loaded.
     * Uses a static initializer approach to avoid repeated directory creation attempts.
     *
     * @return The initialized temporary directory path, or null if creation fails
     */
    private static Path initializeAppTempDir() {
        try {
            Path tempDir = Path.of(System.getProperty("java.io.tmpdir"), "struts2-debug");
            Files.createDirectories(tempDir);
            LOG.debug("Initialized application temp directory: {}", tempDir);
            return tempDir;
        } catch (IOException e) {
            LOG.warn("Failed to initialize application temp directory", e);
            return null;
        }
    }

    private LinkedList<byte[]> buffers;
    private byte[] buffer;
    private int index;
    private int size;
    private final int blockSize;
    private boolean closed;

    public FastByteArrayOutputStream() {
        this(DEFAULT_BLOCK_SIZE);
    }

    public FastByteArrayOutputStream(int blockSize) {
        buffer = new byte[this.blockSize = blockSize];
    }

    public void writeTo(OutputStream out) throws IOException {
        if (buffers != null) {
            for (byte[] bytes : buffers) {
                out.write(bytes, 0, blockSize);
            }
        }
        out.write(buffer, 0, index);
    }

    public void writeTo(RandomAccessFile out) throws IOException {
        if (buffers != null) {
            for (byte[] bytes : buffers) {
                out.write(bytes, 0, blockSize);
            }
        }
        out.write(buffer, 0, index);
    }

    /**
     * This is a patched method (added for common Writer, needed for tests)
     * @param out Writer
     * @param encoding Encoding
     * @throws IOException If some output failed
     */
    public void writeTo(Writer out, String encoding) throws IOException {
        if (encoding != null) {
            CharsetDecoder decoder = getDecoder(encoding);
            // Create buffer for characters decoding
            CharBuffer charBuffer = CharBuffer.allocate(buffer.length);
            // Create buffer for bytes
            float bytesPerChar = decoder.charset().newEncoder().maxBytesPerChar();
            ByteBuffer byteBuffer = ByteBuffer.allocate((int) (buffer.length + bytesPerChar));
            if (buffers != null) {
                for (byte[] bytes : buffers) {
                    decodeAndWriteOut(out, bytes, bytes.length, byteBuffer, charBuffer, decoder, false);
                }
            }
            decodeAndWriteOut(out, buffer, index, byteBuffer, charBuffer, decoder, true);
        } else {
            if (buffers != null) {
                for (byte[] bytes : buffers) {
                    writeOut(out, bytes, bytes.length);
                }
            }
            writeOut(out, buffer, index);
        }
    }

    private CharsetDecoder getDecoder(String encoding) {
        Charset charset = Charset.forName(encoding);
        return charset.newDecoder().
                onMalformedInput(CodingErrorAction.REPORT).
                onUnmappableCharacter(CodingErrorAction.REPLACE);
    }

    /**
     * This is a patched method (standard)
     * @param out Writer
     * @param encoding Encoding
     * @throws IOException If some output failed
     */
    public void writeTo(JspWriter out, String encoding) throws IOException {
        try {
            writeTo((Writer) out, encoding);
        } catch (IOException e) {
            writeToFile();
            throw e;
        } catch (Throwable e) {
            writeToFile();
            throw new RuntimeException(e);
        }
    }

    /**
     * This method is needed only for debug and test scenarios when output fails to write to JspWriter.
     * It securely creates a temporary file in a controlled application directory using UUID-based naming
     * to prevent path traversal attacks and filename collisions.
     *
     * Security Note: This method uses UUID-based naming in a controlled directory rather than
     * File.createTempFile() to comply with secure temporary file creation practices. The caller
     * is responsible for cleanup of this file if needed for long-term storage.
     */
    private void writeToFile() {
        try {
            File tempFile = createSecureTemporaryFile();
            try (FileOutputStream fileOutputStream = new FileOutputStream(tempFile)) {
                writeTo(fileOutputStream);
                LOG.debug("Debug output written to: {}", tempFile.getAbsolutePath());
            }
        } catch (IOException e) {
            LOG.debug("Failed to write debug output to file", e);
        }
    }

    /**
     * Creates a secure temporary file in a controlled application directory with UUID-based naming.
     *
     * Security Implementation:
     * - Uses a pre-initialized controlled directory (java.io.tmpdir/struts2-debug) instead of system defaults
     * - Uses UUID-based naming to prevent filename predictability and collisions
     * - Directory is created once during class initialization for optimal performance
     *
     * @return A File object pointing to the newly created temporary file
     * @throws IOException If the application temp directory is not available or file creation fails
     */
    private File createSecureTemporaryFile() throws IOException {
        if (APP_TEMP_DIR == null) {
            throw new IOException("Application temp directory not available for debug output");
        }

        // Use UUID-based naming to prevent predictability and collisions
        String uid = UUID.randomUUID().toString().replace("-", "_");
        String fileName = "debug_" + uid + ".log";
        Path tempFilePath = APP_TEMP_DIR.resolve(fileName);

        LOG.debug("Creating secure temporary file: {}", tempFilePath);
        return tempFilePath.toFile();
    }

    private void writeOut(Writer out, byte[] bytes, int length) throws IOException {
        out.write(new String(bytes, 0, length));
    }

    private static void decodeAndWriteOut(Writer writer, byte[] bytes, int length, ByteBuffer in, CharBuffer out, CharsetDecoder decoder, boolean endOfInput) throws IOException {
        // Append bytes to current buffer
        // Previous data maybe partially decoded, this part will appended to previous
        in.put(bytes, 0, length);
        // To begin processing of data
        in.flip();
        decodeAndWriteBuffered(writer, in, out, decoder, endOfInput);
    }

    private static void decodeAndWriteBuffered(Writer writer, ByteBuffer in, CharBuffer out, CharsetDecoder decoder, boolean endOfInput) throws IOException {
        // Decode
        CoderResult result;
        do {
            result = decodeAndWrite(writer, in, out, decoder, endOfInput);
            // Check that all data are decoded
            if (in.hasRemaining()) {
                // Move remaining to top of buffer
                in.compact();
                if (result.isOverflow() && !result.isError()) {  // isError covers isMalformed and isUnmappable
                    // Not all buffer chars decoded, spin it again
                    // Set to begin
                    in.flip();
                }
            } else {
                // Clean up buffer
                in.clear();
            }
        } while (in.hasRemaining() && result.isOverflow() && !result.isError());  // isError covers isMalformed and isUnmappable

        if (result.isError()) {
            if (LOG.isWarnEnabled()) {
                // Provide a log warning when the decoding fails (prior to 2.5.19 it failed silently).
                // Note: Set FastByteArrayOutputStream's Logger level to error or higher to suppress this log warning.
                LOG.warn("Buffer decoding-in-to-out [{}] failed, coderResult [{}]", decoder.charset().name(), result.toString());
            }
        }
    }

    private static CoderResult decodeAndWrite(Writer writer, ByteBuffer in, CharBuffer out, CharsetDecoder decoder, boolean endOfInput) throws IOException {
        CoderResult result = decoder.decode(in, out, endOfInput);
        // To begin processing of decoded data
        out.flip();
        // Output
        writer.write(out.toString());
        // Clear output to avoid infinite loops, see WW-4383
        out.clear();
        return result;
    }

    public int getSize() {
        return size + index;
    }

    public byte[] toByteArray() {
        byte[] data = new byte[getSize()];
        int position = 0;
        if (buffers != null) {
            for (byte[] bytes : buffers) {
                System.arraycopy(bytes, 0, data, position, blockSize);
                position += blockSize;
            }
        }
        System.arraycopy(buffer, 0, data, position, index);
        return data;
    }

    public String toString() {
        return new String(toByteArray());
    }

    protected void addBuffer() {
        if (buffers == null) {
            buffers = new LinkedList<>();
        }
        buffers.addLast(buffer);
        buffer = new byte[blockSize];
        size += index;
        index = 0;
    }

    public void write(int datum) throws IOException {
        if (closed) {
            throw new IOException("Stream closed");
        }
        if (index == blockSize) {
            addBuffer();
        }
        buffer[index++] = (byte) datum;
    }

    public void write(byte[] data, int offset, int length) throws IOException {
        if (data == null) {
            throw new NullPointerException();
        }
        if (offset < 0 || offset + length > data.length || length < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (closed) {
            throw new IOException("Stream closed");
        }
        if (index + length > blockSize) {
            do {
                if (index == blockSize) {
                    addBuffer();
                }
                int copyLength = blockSize - index;
                if (length < copyLength) {
                    copyLength = length;
                }
                System.arraycopy(data, offset, buffer, index, copyLength);
                offset += copyLength;
                index += copyLength;
                length -= copyLength;
            } while (length > 0);
        } else {
            System.arraycopy(data, offset, buffer, index, length);
            index += length;
        }
    }

    public void close() {
        closed = true;
    }
}
