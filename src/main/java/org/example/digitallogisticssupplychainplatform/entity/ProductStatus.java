package org.example.digitallogisticssupplychainplatform.entity;

public enum ProductStatus {
    ACTIVE,            // Produit disponible et actif dans le système
    INACTIVE,          // Produit désactivé (non visible ou non vendable)
    PENDING,           // En attente de validation ou d'approbation
    OUT_OF_STOCK,      // En rupture de stock
    IN_STOCK,          // Disponible en stock
    DISCONTINUED,      // Produit abandonné / plus fabriqué
    UNDER_REVIEW,      // En cours d’évaluation avant mise en vente
    RESERVED,          // Réservé pour une commande
    DAMAGED,           // Produit endommagé
    RETURNED,          // Produit retourné par un client
    DELETED            // Supprimé logiquement (soft delete)
}
