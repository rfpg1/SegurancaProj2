package facade.exceptions;

public class ApplicationException extends Exception {

	private String message;

	public ApplicationException(String message) {
		this.message = message;
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = -3803060827223115611L;

	@Override
	public String getMessage() {
		return this.message;
	}

}
