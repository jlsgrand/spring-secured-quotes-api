package co.simplon.springsecuredquotesapi.controller;

import co.simplon.springsecuredquotesapi.model.AppUser;
import co.simplon.springsecuredquotesapi.repository.AppUserRepository;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/admin/users")
public class AppUserController {

    private AppUserRepository appUserRepository;

    public AppUserController(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    /**
     * Fonction de récupération de tous les utilisateurs (de manière paginée)
     *
     * @param pageable Les paramètres de pagination que l'on veut spécifier
     *                 On peut utiliser :
     *                 page=x pour spécifier le numéro de page
     *                 size=y pour spécifier la taille de la page
     *                 sort=sortParams pour spécifier le tri des données
     *                 Exemple d'appel : /admin/users?page=2&size=35&sort=username,desc,ignorecase
     * @return le contenu de la page demandée
     */
    @GetMapping
    public ResponseEntity<List<AppUser>> getAllUsers(Pageable pageable) {
        return ResponseEntity.ok(appUserRepository.findAll(pageable).getContent());
    }

    /**
     * TODO
     * @return
     */
    @GetMapping("/count")
    ResponseEntity<Long> getTotalUsersNumber() {
        return ResponseEntity.ok(appUserRepository.count());
    }
}
