package com.keyup.auth.model.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "roles",
        uniqueConstraints = {@UniqueConstraint(columnNames = {"user_id", "role"})})
@Getter
@Setter
@NoArgsConstructor
public class RoleEntity implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="id")
    private Long id;

    private String role;
}
