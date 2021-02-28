package com.rsa.util;

import java.security.SecureRandom;

public class RandomUtil {
  private static final String CONSTANT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public static final String generateString(final int length) {
    final StringBuilder sb = new StringBuilder(length);
    for (int i = 0; i < length; i++)
      sb.append(CONSTANT_CHARS.charAt(SECURE_RANDOM.nextInt(CONSTANT_CHARS.length())));
    return sb.toString();
  }
}
