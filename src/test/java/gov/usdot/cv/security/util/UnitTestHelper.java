package gov.usdot.cv.security.util;

import java.util.Enumeration;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

/**
 * Unit test logging initializer
 */
public class UnitTestHelper {
	
	/**
	 * Sets logging level from boolean
	 * @param isDebugOutput if true, logging level is set to DEBUG, otherwise it's set to INFO
	 */
	public static void initLog4j(boolean isDebugOutput) {
		initLog4j(isDebugOutput ? Level.DEBUG : Level.INFO);
	}
	
	/**
	 * Set logging level to the level specified
	 * @param level new logging level
	 */
	public static void initLog4j(Level level) {
	    Logger rootLogger = Logger.getRootLogger();
	    @SuppressWarnings("rawtypes")
		Enumeration appenders = rootLogger.getAllAppenders();
	    if ( appenders == null || !appenders.hasMoreElements() ) {
		    rootLogger.setLevel(level);
		    rootLogger.addAppender(new ConsoleAppender(new PatternLayout("%-6r [%p] %c - %m%n")));
	    }
	}
}
