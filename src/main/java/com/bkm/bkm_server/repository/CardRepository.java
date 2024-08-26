package com.bkm.bkm_server.repository;

import com.bkm.bkm_server.model.Card;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CardRepository extends JpaRepository<Card, Long> {
}
