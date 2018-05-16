package discord4j.benchmarks;

import com.goterl.lazycode.lazysodium.LazySodium;
import com.goterl.lazycode.lazysodium.Sodium;
import com.iwebpp.crypto.TweetNacl;
import com.iwebpp.crypto.TweetNaclFast;
import com.muquit.libsodiumjna.SodiumLibrary;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;
import com.sun.jna.Platform;
import org.abstractj.kalium.crypto.SecretBox;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.concurrent.ThreadLocalRandom;

@Threads(Threads.MAX)
public class MyBenchmark {

    public static final int PRIVATE_KEY_LEN = 32;
    public static final int PUBLIC_KEY_LEN = 32;
    public static final int TOTAL_KEY_LEN = PRIVATE_KEY_LEN + PUBLIC_KEY_LEN;
    public static final int NONCE_LEN = 24;
    public static final int DATA_LEN = 1024 * 8;

//    static {
//        System.setProperty("java.io.tmpdir", "./");
//    }

    @State(Scope.Thread)
    public static class SodiumState {

        public byte[] key = {};
        public byte[] nonce = {};
        public byte[] data = {};
        public byte[] dataZeroes = {};

        public LazySodium lazySodium;

        public static byte[] randArray(int len) {
            ThreadLocalRandom random = ThreadLocalRandom.current();
            byte[] array = new byte[len];
            random.nextBytes(array);
            return array;
        }

        @Setup(Level.Trial)
        public void doSetup() {
            key = randArray(PUBLIC_KEY_LEN);
            nonce = randArray(NONCE_LEN);

            data = randArray(DATA_LEN);
            dataZeroes = new byte[DATA_LEN];

            //Have to do this for libsodiumjna
            String libraryPath;
            if (Platform.isMac()) {
                // MacOS
                libraryPath = "/usr/local/lib/libsodium.dylib";
            } else if (Platform.isWindows()) {
                // Windows
                libraryPath = "C:/libsodium/libsodium.dll";
            } else {
                // Linux
                libraryPath = "/usr/local/lib/libsodium.so";
            }
            SodiumLibrary.setLibraryPath(libraryPath);

            lazySodium = new LazySodium(Sodium.loadJava());
        }

        @TearDown(Level.Trial)
        public void doTearDown() {
            key = new byte[0];
            nonce = new byte[0];
            data = new byte[0];
            dataZeroes = new byte[0];

            lazySodium = null;
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.All)
    public void testTweetNaclFast(SodiumState state, Blackhole blackhole) {
        byte[] box = new TweetNaclFast.SecretBox(state.key).box(state.data, state.nonce);
        blackhole.consume(new TweetNaclFast.SecretBox(state.key).open(box, state.nonce));
    }

    @Benchmark
    @BenchmarkMode(Mode.All)
    public void testTweetNacl(SodiumState state, Blackhole blackhole) {
        byte[] box = new TweetNacl.SecretBox(state.key).box(state.data, state.nonce);
        blackhole.consume(new TweetNacl.SecretBox(state.key).open(box, state.nonce));
    }

    @Benchmark
    @BenchmarkMode(Mode.All)
    public void testKalium(SodiumState state, Blackhole blackhole) {
        SecretBox box = new SecretBox(state.key);
        byte[] encrypted = box.encrypt(state.nonce, state.data);
        blackhole.consume(box.decrypt(state.nonce, encrypted));
    }

    @Benchmark
    @BenchmarkMode(Mode.All)
    public void testLibsodiumJna(SodiumState state, Blackhole blackhole) throws SodiumLibraryException {
        byte[] encrypted = SodiumLibrary.cryptoSecretBoxEasy(state.data, state.nonce, state.key);
        blackhole.consume(SodiumLibrary.cryptoSecretBoxOpenEasy(encrypted, state.nonce, state.key));
    }

    @Benchmark
    @BenchmarkMode(Mode.All)
    public void testLazySodium(SodiumState state, Blackhole blackhole) throws SodiumLibraryException {
        byte[] encrypted = new byte[com.goterl.lazycode.lazysodium.interfaces.SecretBox.MACBYTES + DATA_LEN];
        state.lazySodium.cryptoSecretBoxEasy(encrypted, state.data, DATA_LEN, state.nonce, state.key);
        byte[] message = new byte[DATA_LEN];
        state.lazySodium.cryptoSecretBoxOpenEasy(message, encrypted, encrypted.length, state.nonce, state.key);
        blackhole.consume(message);
    }

//    @Benchmark FIXME: Broken! Native library loading is completely borked
//    @BenchmarkMode(Mode.All)
//    public void testLibsodiumJni(SodiumState state, Blackhole blackhole) throws SodiumLibraryException {
//        org.libsodium.jni.crypto.SecretBox box = new org.libsodium.jni.crypto.SecretBox(state.key);
//        byte[] encrypted = box.encrypt(state.nonce, state.data);
//        blackhole.consume(box.decrypt(state.nonce, encrypted));
//    }
}