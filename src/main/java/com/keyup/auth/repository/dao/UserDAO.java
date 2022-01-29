package com.keyup.auth.repository.dao;

import com.keyup.auth.model.entity.UserEntity;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserDAO extends CrudRepository<UserEntity,Long> {

    Optional<UserEntity> findByUsername(String username);

}
