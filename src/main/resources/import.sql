
INSERT INTO USERS (USERNAME, PASSWORD, ENABLED) VALUES ('fede','$2a$10$O9wxmH/AeyZZzIS09Wp8YOEMvFnbRVJ8B4dmAMVSGloR62lj.yqXG',1);
INSERT INTO USERS (USERNAME, PASSWORD, ENABLED) VALUES ('admin','$2a$10$DOMDxjYyfZ/e7RcBfUpzqeaCs8pLgcizuiQWXPkU35nOhZlFcE9MS',1);

INSERT INTO ROLES (USER_ID, ROLE) VALUES (1,'ROLE_USER');
INSERT INTO ROLES (USER_ID, ROLE) VALUES (2,'ROLE_ADMIN');
INSERT INTO ROLES (USER_ID, ROLE) VALUES (2,'ROLE_USER');