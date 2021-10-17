package co.simplon.springsecuredquotesapi.repository;

import co.simplon.springsecuredquotesapi.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    /**
     * Fonction de récupération d'un utilisateur par son username (en ignorant la casse)
     *
     * @param username le username à chercher
     * @return un optional avec l'utilisateur s'il existe dans la BDD
     */
    Optional<AppUser> findByUsernameIgnoreCase(String username);
}
