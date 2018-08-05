package org.tron.walletcli;

import java.io.IOException;
import org.tron.core.exception.CipherException;


public class AirDrop {

  public static void main(String[] args) throws IOException, CipherException {
    Client client = new Client();
    client.login("Rcc03083210".toCharArray());
    client.airDrop("Skypeople", 99);
  }
}
