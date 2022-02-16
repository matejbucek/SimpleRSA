package cz.mbucek.rsa;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.IntStream;

public class RSA {

	public static KeyPair generatePrivateAndPublicKeys() {
		//Musí být prvočísla. Doporučuje se, aby byly v podobném rozsahu a lišili se jen o pár míst.
		//Pokud chceme šifrovat text, doporučuji minimálně toto nastavení: int p = 61, q = 53;
		//Tato prvočísla jsou základ pro klíče. Pro každý pár musíme tudíž mít jiná prvočísla (náhodná).
		//Tato čísla jsou soukromá a nesmí je nikdo zjistit.
		int p = 61, q = 53;
		
		//Modulo - použito v privátním i veřejném klíči
		int n = p * q;
		
		//Počet Co-Prime čísel pro p a q
		//Co-Prime je číslo, které nemá žádný společný faktor s daným číslem.
		int ctf = ctf(p, q);
		
		//Co-Prime číslo pro n a ctf
		//Součást veřejného klíče
		int e = generateCoprimes(n, ctf);
		
		//Součást privátního klíče
		int d = modInverse(e, ctf);
		if(d == e) d += ctf;
		
		return new KeyPair(new PrivateKey(n, d), new PublicKey(n, e));
	}
	
	/**
	 * Zašifrování hodnoty value pomocí veřejného klíče.
	 * 
	 * <code>c ≡ m<sup>e</sup> (mod n)</code>
	 * 
	 * @param key veřejný klíč
	 * @param value hodnota
	 * @return zašifrovaná hodnota
	 */
	public static int encrypt(PublicKey key, int value) {
		return BigInteger.valueOf(value).modPow(BigInteger.valueOf(key.e()), BigInteger.valueOf(key.n())).intValue();
	}
	
	/**
	 * Dešifrování hodnoty value pomocí privátního klíče.
	 * 
	 * <code>m ≡ c<sup>d</sup> (mod n)</code>
	 * 
	 * @param key privátní klíč
	 * @param value hodnota
	 * @return dešifrovaná hodnota
	 */
	public static int decrypt(PrivateKey key, int value) {
		return BigInteger.valueOf(value).modPow(BigInteger.valueOf(key.d()), BigInteger.valueOf(key.n())).intValue();
	}
	
	public static int[] encrypt(PublicKey key, String text) {
		return text.chars().map(v -> encrypt(key, v)).toArray();
	}
	
	public static String decrypt(PrivateKey key, int[] data) {
		return charArrayToString(IntStream.of(data).map(v -> decrypt(key, v)));
	}
	
	public static String charArrayToString(IntStream stream) {
		var text = new StringBuilder();
		stream.forEach(v -> text.append((char) v));
		return text.toString();
	}
	
	public static List<Integer> sieveOfEratosthenes(int n) {
	    boolean prime[] = new boolean[n + 1];
	    Arrays.fill(prime, true);
	    for (int p = 2; p * p <= n; p++) {
	        if (prime[p]) {
	            for (int i = p * 2; i <= n; i += p) {
	                prime[i] = false;
	            }
	        }
	    }
	    List<Integer> primeNumbers = new LinkedList<>();
	    for (int i = 2; i <= n; i++) {
	        if (prime[i]) {
	            primeNumbers.add(i);
	        }
	    }
	    return primeNumbers;
	}
	
	/**
	 * Vygeneruje číslo, které je Co-Prime pro n i ctf.
	 * 
	 * @param n modulo
	 * @param ctf ctf
	 * @return Co-Prime
	 */
	public static int generateCoprimes(int n, int ctf) {
		var nPrimes = sieveOfEratosthenes(n);
		var ctfPrimes = sieveOfEratosthenes(ctf);
		var coprimes = new ArrayList<Integer>();
		
		for(var prime : nPrimes) {
			if(ctfPrimes.contains(prime) && areCoprimes(prime, n) && areCoprimes(prime, ctf)) coprimes.add(prime);
		}
		
		return coprimes.get(coprimes.size() - 1);
	}
	
	/**
	 * Modular Multiplicative Inverse
	 * 
	 * <code>(e * d) (mod ctf) = 1</code>
	 * 
	 * @param e součást veřejného klíče
	 * @param ctf ctf
	 * @return d - součást privátního klíče
	 */
	public static int modInverse(int e, int ctf) {
        //for (int x = 1; x < ctf; x++)
        //    if (((e%ctf) * (x%ctf)) % ctf == 1)
        //    	System.out.println(x);
		return BigInteger.valueOf(e).modInverse(BigInteger.valueOf(ctf)).intValue();
	}
	
	/**
	 * Carmichael's Totient Function
	 * 
	 * @param p prvočíslo
	 * @param q prvočíslo
	 * @return λ(n)
	 */
	public static int ctf(int p, int q) {
		return lcm(p - 1, q - 1);
	}
	
	/**
	 * Nejmenší společný násobek pomocí Euclidean Algorithm.
	 * 
	 * @param a číslo
	 * @param b číslo
	 * @return nejmenší společný násobek
	 */
	public static int lcm(int a, int b) {
		return Math.abs(a * b)/gcd(a, b);
	}
	
	/**
	 * Nejvyšší společný dělitel pomocí Euclidean Algorithm.
	 * 
	 * @param a číslo
	 * @param b číslo
	 * @return nejvyšší společný dělitel
	 */
	public static int gcd(int a, int b) {
		if(b == 0) return a;
		return gcd(b, a % b);
	}
	
	/**
	 * Vrací <code>true</code>, pokud jsou čísla Co-Prime.
	 * 
	 * @param a číslo
	 * @param b číslo
	 * @return jsou/nejsou co-prime
	 */
	public static boolean areCoprimes(int a, int b) {
		return gcd(a, b) == 1;
	}
}
