package cz.mbucek.rsa;

import java.util.stream.IntStream;

public class Main {

	public static void main(String[] args) {
		var keys = RSA.generatePrivateAndPublicKeys();
		System.out.println(keys);
		
		var text = """
				Hi, how are you doing today?
				This is just an example text.
				Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aliquam erat volutpat. Nulla accumsan, elit sit amet varius semper, nulla mauris mollis quam, tempor suscipit diam nulla vel leo. Nunc tincidunt ante vitae massa. Vivamus porttitor turpis ac leo. Aenean fermentum risus id tortor. Fusce tellus. Nulla quis diam. Duis ante orci, molestie vitae vehicula venenatis, tincidunt ac pede. Nulla quis diam. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Mauris tincidunt sem sed arcu. Donec ipsum massa, ullamcorper in, auctor et, scelerisque sed, est. Proin in tellus sit amet nibh dignissim sagittis. Proin pede metus, vulputate nec, fermentum fringilla, vehicula vitae, justo. Vivamus porttitor turpis ac leo. Fusce suscipit libero eget elit. Aliquam erat volutpat. Curabitur sagittis hendrerit ante.
				""";
		
		var encrypted = RSA.encrypt(keys.pub(), text);
		System.out.println(RSA.charArrayToString(IntStream.of(encrypted)));
		var decrypted = RSA.decrypt(keys.priv(), encrypted);
		System.out.println(decrypted);
	}

}
