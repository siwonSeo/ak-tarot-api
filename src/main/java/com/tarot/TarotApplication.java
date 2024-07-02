package com.tarot;

import com.tarot.service.TarotDataService;
import com.tarot.service.TarotService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.json.simple.parser.ParseException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.io.IOException;

@EnableJpaAuditing
@RequiredArgsConstructor
@SpringBootApplication
public class TarotApplication {
	private final TarotDataService tarotDataService;
	public static void main(String[] args) {
		SpringApplication.run(TarotApplication.class, args);
	}

//	@PostConstruct
	private void init() throws IOException, ParseException {
		tarotDataService.setDefaultData();
	}
}
