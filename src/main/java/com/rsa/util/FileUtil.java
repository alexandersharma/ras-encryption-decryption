package com.rsa.util;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.xml.bind.DatatypeConverter;

public class FileUtil {

  public static final void writeFile(final String filepath, final String data) {
    writeFile(filepath, data.getBytes());
  }

  public static final void writeFileHexFormat(final String filepath, final byte[] data) {
    writeFile(filepath, DatatypeConverter.printHexBinary(data));
  }

  public static final void writeFile(final String filepath, final byte[] data) {
    try (final FileOutputStream outputStream = new FileOutputStream(filepath)) {
      outputStream.write(data);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static final byte[] readFileHexFormat(final String filepath) {
    try (final BufferedReader reader = Files.newBufferedReader(Paths.get(filepath), StandardCharsets.UTF_8)) {
      final StringBuilder sb = new StringBuilder();
      String line;

      while ((line = reader.readLine()) != null) {
        sb.append(line);
      }

      return DatatypeConverter.parseHexBinary(sb.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }
}
