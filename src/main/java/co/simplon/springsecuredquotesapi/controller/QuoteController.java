package co.simplon.springsecuredquotesapi.controller;

import co.simplon.springsecuredquotesapi.model.AppUser;
import co.simplon.springsecuredquotesapi.model.Quote;
import co.simplon.springsecuredquotesapi.repository.QuoteRepository;
import co.simplon.springsecuredquotesapi.security.AppUserDetailsService;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/quotes")
public class QuoteController {

    private QuoteRepository quoteRepository;
    private AppUserDetailsService appUserDetailsService;

    public QuoteController(QuoteRepository quoteRepository, AppUserDetailsService appUserDetailsService) {
        this.quoteRepository = quoteRepository;
        this.appUserDetailsService = appUserDetailsService;
    }

    /**
     * Fonction de récupération de toutes les citations (de manière paginée)
     *
     * @param pageable Les paramètres de pagination que l'on veut spécifier
     *                 On peut utiliser :
     *                 page=x pour spécifier le numéro de page
     *                 size=y pour spécifier la taille de la page
     *                 sort=sortParams pour spécifier le tri des données
     *                 Exemple d'appel : /api/quotes?page=2&size=35&sort=movie,asc,ignorecase
     * @return le contenu de la page demandée
     */
    @GetMapping
    public ResponseEntity<List<Quote>> getAllQuotes(Pageable pageable) {
        return ResponseEntity.ok(quoteRepository.findAll(pageable).getContent());
    }

    /**
     * TODO
     * @return
     */
    @GetMapping("/count")
    ResponseEntity<Long> getTotalQuotesNumber() {
        return ResponseEntity.ok(quoteRepository.count());
    }

    /**
     * Fonction de récupération d'une citation avec son id
     *
     * @param id l'id de la citation à retrouver
     * @return La citation si l'id correspond à une citation de la BDD
     * Une erreur 404 sinon
     */
    @GetMapping("/{id}")
    public ResponseEntity<Quote> getQuote(@PathVariable Long id) {
        Optional<Quote> quote = quoteRepository.findById(id);
        if (quote.isPresent()) {
            return ResponseEntity.ok(quote.get());
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Fonction de création d'une citation
     *
     * @param quote la citation à créer
     * @return La citation fraîchement créée si la citation n'a pas d'ID et que son contenu est défini
     * Une erreur 400 sinon
     */
    @PostMapping
    public ResponseEntity<Quote> createQuote(@RequestBody Quote quote, @AuthenticationPrincipal User user) {
        /*
          Pour la simplicité de l'exemple on retourne juste une erreur 400 si l'id existe ou site la citation n'a pas
          de contenu mais pour faire propre, il faudrait renvoyer un message d'erreur différent dans chaque cas.
          ==> si vous voulez regarder ça de plus près allez voir le ControllerAdvice
         */
        if (quote.getId() != null || quote.getContent() == null || quote.getContent().isBlank()) {
            return ResponseEntity.badRequest().build();
        } else {
            Optional<AppUser> author = appUserDetailsService.loadAppUserByUsername(user.getUsername());
            author.ifPresent(quote::setAuthor);

            return ResponseEntity.ok(quoteRepository.save(quote));
        }
    }

    /**
     * Fonction de mise à jour d'une citation
     *
     * @param quote la citation à mettre à jour
     * @return La citation fraîchement mise à jour si la citation a un ID
     * Une erreur 400 sinon
     */
    @PutMapping
    public ResponseEntity<Quote> updateQuote(@RequestBody Quote quote, @AuthenticationPrincipal User user) {
        if (quote.getId() == null) {
            return ResponseEntity.badRequest().build();
        } else {
            Optional<AppUser> author = appUserDetailsService.loadAppUserByUsername(user.getUsername());
            author.ifPresent(quote::setAuthor);

            return ResponseEntity.ok(quoteRepository.save(quote));
        }
    }

    /**
     * Fonction de suppression d'un citation avec son id
     *
     * @param id L'id de la citation à supprimer
     * @return Une réponse HTTP avec le statut NO_CONTENT
     */
    @DeleteMapping("/{id}")
    public ResponseEntity deleteQuote(@PathVariable Long id) {
        quoteRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}
