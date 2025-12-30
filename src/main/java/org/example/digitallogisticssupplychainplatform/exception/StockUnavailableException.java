
package org.example.digitallogisticssupplychainplatform.exception;


public class StockUnavailableException extends RuntimeException {
    public StockUnavailableException(String message) {
        super(message);
    }

    public StockUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
