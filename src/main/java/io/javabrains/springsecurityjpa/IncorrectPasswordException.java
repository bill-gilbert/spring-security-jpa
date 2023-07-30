package io.javabrains.springsecurityjpa;

public class IncorrectPasswordException extends RuntimeException {
    public IncorrectPasswordException() {
        super();
    }

    public IncorrectPasswordException(String message) {
        super(message);
    }

    public IncorrectPasswordException(String message, Throwable cause) {
        super(message, cause);
    }

    public IncorrectPasswordException(Throwable cause) {
        super(cause);
    }

    protected IncorrectPasswordException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
