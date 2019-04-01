package co.nayuta.lightning;

import javax.validation.constraints.NotNull;


class PtarmiganNative {
    native static int ptarmStart(@NotNull String alias, @NotNull String ipAddress, int Port);

    public static void main(String args[]) {
        System.out.println("Hello, PtarmiganNative!");
        int ret = ptarmStart("ueno", "", 3333);
        System.out.println("result=" + ret);
    }

    static {
        System.loadLibrary("ptarm");
    }
}
