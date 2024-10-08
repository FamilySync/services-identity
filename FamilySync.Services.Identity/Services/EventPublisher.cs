﻿namespace FamilySync.Services.Identity.Services;

public interface IEventPublisher
{
    public Task Logout(Guid userID);
}

public class EventPublisher : IEventPublisher
{
    private readonly ILogger<EventPublisher> _logger;

    public EventPublisher(ILogger<EventPublisher> logger)
    {
        _logger = logger;
    }

    public Task Logout(Guid userID)
    {
        _logger.LogError("Failed to publish logout event for user with ID {id}. NOT IMPLEMENTED!", userID);
        
        return Task.CompletedTask;
    }
}